import argparse
import atexit
import json
import os
import signal
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
from collections import deque
from datetime import datetime

import requests
from colorama import Fore, Style, init

init(autoreset=True)

_xray_name = "xray.exe" if sys.platform == "win32" else "xray"
XRAY = os.path.join(os.path.dirname(os.path.abspath(__file__)), _xray_name)
CONFIGS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "configs.txt")
XRAY_CONFIG = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "xrayconfig.json"
)
HISTORY_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "config_history.json"
)

SOCKS_PORT = 4567
SOCKS_LISTEN = "0.0.0.0"
SNI_PORT = 40443
BASE_TEST_PORT = 19000
TEST_URL = "https://cachefly.cachefly.net/1mb.test"
TEST_TIMEOUT = 15
CHECK_INTERVAL = 30 * 60

# ── Scoring system weights ─────────────────────────────────────────────────────
W_SPEED = 0.4  # Weight for raw speed score
W_STABILITY = 0.6  # Weight for stability score
SWITCH_THRESHOLD = 0.2  # 20% - switch only if new config is this much better
HISTORY_WINDOW = 6  # Keep last 6 test results per config

# ── Global state ───────────────────────────────────────────────────────────────
_active_proc = None
config_history = {}  # {config_name: deque([(timestamp, speed, success), ...])}
history_lock = threading.Lock()


def _set_active_proc(proc):
    global _active_proc
    _active_proc = proc


def _cleanup():
    if _active_proc and _active_proc.poll() is None:
        print(Fore.YELLOW + "\nStopping Xray...")
        _active_proc.terminate()
        try:
            _active_proc.wait(timeout=3)
        except Exception:
            _active_proc.kill()
        print(Fore.GREEN + "Xray stopped.")

    # Save history on exit
    save_history()


atexit.register(_cleanup)

if sys.platform != "win32":

    def _sigterm_handler(signum, frame):
        sys.exit(0)

    signal.signal(signal.SIGTERM, _sigterm_handler)


# ── History management ─────────────────────────────────────────────────────────


def load_history():
    """Load config performance history from disk"""
    global config_history
    if os.path.exists(HISTORY_FILE):
        try:
            with open(HISTORY_FILE, "r") as f:
                data = json.load(f)
                # Convert stored lists back to deques
                for name, entries in data.items():
                    config_history[name] = deque(
                        [(e[0], e[1], e[2]) for e in entries], maxlen=HISTORY_WINDOW
                    )
        except Exception:
            pass


def save_history():
    """Save config performance history to disk"""
    with history_lock:
        serializable = {}
        for name, entries in config_history.items():
            serializable[name] = list(entries)
        try:
            with open(HISTORY_FILE, "w") as f:
                json.dump(serializable, f, indent=2)
        except Exception:
            pass


def update_history(config_name, speed, success):
    """Record a test result for a config"""
    with history_lock:
        if config_name not in config_history:
            config_history[config_name] = deque(maxlen=HISTORY_WINDOW)
        config_history[config_name].append((time.time(), speed, success))


def calculate_score(config_name, current_speed):
    """
    Calculate weighted score combining speed and stability.
    Score = (W_SPEED * speed_score) + (W_STABILITY * stability_score)
    Returns 0 if no history or all failures.
    """
    with history_lock:
        if config_name not in config_history or len(config_history[config_name]) == 0:
            # No history - use only current speed
            return current_speed * W_SPEED

        entries = config_history[config_name]

        # Calculate stability: proportion of successful tests
        successes = sum(1 for _, _, success in entries if success)
        stability_score = successes / len(entries) if entries else 0

        # Calculate moving average speed (only successful tests)
        successful_speeds = [speed for _, speed, success in entries if success]
        avg_speed = (
            sum(successful_speeds) / len(successful_speeds) if successful_speeds else 0
        )

        # Weighted score
        return (W_SPEED * current_speed) + (W_STABILITY * stability_score * avg_speed)


def get_consecutive_failures(config_name):
    """Count consecutive failures for a config"""
    with history_lock:
        if config_name not in config_history:
            return 0
        count = 0
        for _, _, success in reversed(config_history[config_name]):
            if not success:
                count += 1
            else:
                break
        return count


# ── Parsers (unchanged from original) ──────────────────────────────────────────


def _build_stream(params):
    network = params.get("type", "tcp")
    security = params.get("security", "none")

    sni = params.get("sni", "")
    fp = params.get("fp", "")
    pbk = params.get("pbk", "")
    sid = params.get("sid", "")
    flow = params.get("flow", "")
    host = params.get("host", "")
    path = urllib.parse.unquote(params.get("path", "/"))
    service_name = params.get("serviceName", "")
    authority = params.get("authority", "")
    mode = params.get("mode", "auto")

    alpn_raw = params.get("alpn", "")
    alpn = alpn_raw.split(",") if alpn_raw else []

    allow_insecure = params.get("insecure", "0") == "1"

    stream = {"network": network, "security": security}

    if security == "tls":
        tls_settings = {"serverName": sni, "allowInsecure": allow_insecure}

        if fp:
            tls_settings["fingerprint"] = fp

        if alpn:
            tls_settings["alpn"] = alpn

        stream["tlsSettings"] = tls_settings

    elif security == "reality":
        reality_settings = {
            "serverName": sni,
            "fingerprint": fp or "chrome",
            "publicKey": pbk,
            "shortId": sid,
        }

        stream["realitySettings"] = reality_settings

    if network == "ws":
        stream["wsSettings"] = {"path": path, "headers": {"Host": host}}

    elif network == "grpc":
        stream["grpcSettings"] = {
            "serviceName": service_name,
            "authority": authority,
            "multiMode": False,
        }

    elif network == "httpupgrade":
        stream["httpupgradeSettings"] = {"path": path, "host": host}

    elif network == "xhttp":
        stream["xhttpSettings"] = {
            "path": path,
            "host": host,
            "mode": mode,
            "extra": {"xPaddingBytes": "100-1000", "scMaxEachPostBytes": "1000000"},
        }

    elif network == "splithttp":
        stream["splithttpSettings"] = {"path": path, "host": host}

    if flow:
        if "vnext" in params:
            params["vnext"]["users"][0]["flow"] = flow

    return stream


def parse_vless(uri, name):
    parsed = urllib.parse.urlparse(uri)
    params = dict(urllib.parse.parse_qsl(parsed.query))
    return {
        "name": name,
        "protocol": "vless",
        "settings": {
            "vnext": [
                {
                    "address": "127.0.0.1",
                    "port": SNI_PORT,
                    "users": [
                        {"id": parsed.username, "encryption": "none", "level": 0}
                    ],
                }
            ]
        },
        "streamSettings": _build_stream(params),
    }


def parse_trojan(uri, name):
    parsed = urllib.parse.urlparse(uri)
    params = dict(urllib.parse.parse_qsl(parsed.query))
    return {
        "name": name,
        "protocol": "trojan",
        "settings": {
            "servers": [
                {
                    "address": "127.0.0.1",
                    "port": SNI_PORT,
                    "password": urllib.parse.unquote(parsed.username),
                    "level": 1,
                }
            ]
        },
        "streamSettings": _build_stream(params),
    }


def parse_uri(uri):
    uri = uri.strip()
    fragment = ""
    if "#" in uri:
        uri, fragment = uri.rsplit("#", 1)
    name = urllib.parse.unquote(fragment) if fragment else uri[:40]

    if uri.startswith("vless://"):
        return parse_vless(uri, name)
    if uri.startswith("trojan://"):
        return parse_trojan(uri, name)
    return None


# ── Config loading (unchanged) ──────────────────────────────────────────────────


def fetch_subscription(url):
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        content = response.text.strip()

        if "vless://" not in content and "trojan://" not in content:
            try:
                import base64

                padding = len(content) % 4
                if padding:
                    content += "=" * (4 - padding)
                content = base64.b64decode(content).decode("utf-8")
            except Exception:
                pass

        return [line.strip() for line in content.splitlines() if line.strip()]
    except Exception as e:
        print(Fore.RED + f"Failed to fetch subscription {url}: {e}")
        return []


def load_configs(path):
    if not os.path.exists(path):
        print(Fore.RED + f"Error: configs file not found at {path}")
        sys.exit(1)

    servers = []
    skipped = 0

    with open(path, "r") as f:
        lines = [line.strip() for line in f if line.strip()]

    for line in lines:
        if line.startswith("http://") or line.startswith("https://"):
            print(Fore.CYAN + f"Fetching subscription: {line}")
            sub_lines = fetch_subscription(line)
            for sub_line in sub_lines:
                server = parse_uri(sub_line)
                if server:
                    servers.append(server)
                else:
                    skipped += 1
        else:
            server = parse_uri(line)
            if server:
                servers.append(server)
            else:
                skipped += 1

    if skipped:
        print(
            Fore.YELLOW + f"Warning: {skipped} line(s) skipped (unsupported protocol)"
        )
    if not servers:
        print(Fore.RED + "Error: no valid configs found")
        sys.exit(1)

    print(Fore.GREEN + f"Loaded {len(servers)} configs\n")
    time.sleep(2)
    return servers


# ── Xray process management (unchanged) ────────────────────────────────────────


def build_xray_config(server):
    return {
        "log": {"loglevel": "warning"},
        "dns": {
            "servers": [
                {"address": "https://1.1.1.1/dns-query", "skipFallback": False},
                {"address": "8.8.8.8", "skipFallback": False},
            ]
        },
        "inbounds": [
            {
                "tag": "socks",
                "port": SOCKS_PORT,
                "listen": SOCKS_LISTEN,
                "protocol": "socks",
                "settings": {"auth": "noauth", "udp": True},
                "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"]},
            }
        ],
        "outbounds": [
            {
                "tag": "proxy",
                "protocol": server["protocol"],
                "settings": server["settings"],
                "streamSettings": server["streamSettings"],
                "mux": {"enabled": False, "concurrency": -1},
            },
            {"tag": "direct", "protocol": "freedom"},
            {"tag": "block", "protocol": "blackhole"},
        ],
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "rules": [
                {
                    "type": "field",
                    "ip": [
                        "127.0.0.0/8",
                        "10.0.0.0/8",
                        "172.16.0.0/12",
                        "192.168.0.0/16",
                        "::1/128",
                        "fc00::/7",
                    ],
                    "outboundTag": "direct",
                },
                {
                    "type": "field",
                    "network": "udp",
                    "port": "443",
                    "outboundTag": "block",
                },
            ],
        },
    }


def build_test_config(server, port):
    return {
        "log": {"loglevel": "none"},
        "inbounds": [
            {
                "tag": "socks",
                "port": port,
                "listen": "127.0.0.1",
                "protocol": "socks",
                "settings": {"auth": "noauth", "udp": False},
            }
        ],
        "outbounds": [
            {
                "tag": "proxy",
                "protocol": server["protocol"],
                "settings": server["settings"],
                "streamSettings": server["streamSettings"],
                "mux": {"enabled": False, "concurrency": -1},
            }
        ],
    }


def launch_xray(server, current_proc):
    if current_proc and current_proc.poll() is None:
        current_proc.terminate()
        try:
            current_proc.wait(timeout=3)
        except Exception:
            current_proc.kill()
        time.sleep(1)

    if server:
        config = build_xray_config(server)
        with open(XRAY_CONFIG, "w") as f:
            json.dump(config, f, indent=2)

    proc = subprocess.Popen(
        [XRAY, "run", "-c", XRAY_CONFIG],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    _set_active_proc(proc)
    print(
        Fore.GREEN
        + f"Xray launched — PID {proc.pid} — SOCKS on {SOCKS_LISTEN}:{SOCKS_PORT}"
    )
    return proc


# ── Speed testing (unchanged) ──────────────────────────────────────────────────


def measure_speed(port):
    try:
        result = subprocess.run(
            [
                "curl",
                "-s",
                "-o",
                "/dev/null",
                "-w",
                "%{speed_download}",
                "--proxy",
                f"socks5h://127.0.0.1:{port}",
                "--connect-timeout",
                "5",
                "--max-time",
                str(TEST_TIMEOUT),
                TEST_URL,
            ],
            capture_output=True,
            text=True,
            timeout=TEST_TIMEOUT + 3,
        )
        return float(result.stdout.strip()) / 1024 / 1024
    except Exception:
        return 0.0


def test_server(server, port):
    cfg = build_test_config(server, port)
    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
    json.dump(cfg, tmp)
    tmp.close()

    proc = subprocess.Popen(
        [XRAY, "run", "-c", tmp.name],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(1.5)
    speed = measure_speed(port)
    proc.terminate()
    try:
        proc.wait(timeout=3)
    except Exception:
        proc.kill()
    os.unlink(tmp.name)
    return speed


# ── Enhanced testing with scoring ──────────────────────────────────────────────


def run_tests(servers, current_best=None):
    """
    Test all servers and return results sorted by weighted score.
    Also updates rolling history for each config.
    """
    results = []

    for i, server in enumerate(servers):
        port = BASE_TEST_PORT + i
        print(f"  Testing {server['name']}...", end=" ", flush=True)
        speed = test_server(server, port)

        # Update rolling history
        success = speed > 0
        update_history(server["name"], speed, success)

        if not success:
            print(Fore.RED + "failed")
        else:
            print(Fore.YELLOW + f"{speed:.2f} MB/s")

        # Calculate weighted score
        score = calculate_score(server["name"], speed) if success else 0
        results.append((server, speed, score))

    # Sort by weighted score descending
    results.sort(key=lambda x: x[2], reverse=True)
    return results


def print_dynamic_display(ranked, current_best, interval, display_duration=5):
    """
    Show full results for a few seconds, then switch to top 3 + countdown.
    """

    def clear_screen():
        os.system("cls" if os.name == "nt" else "clear")

    def print_full_results():
        clear_screen()
        print(Fore.CYAN + "=" * 60)
        print(Fore.CYAN + "  SPEED TEST RESULTS - COMPLETE OVERVIEW")
        print(Fore.CYAN + "=" * 60)

        for i, (s, spd, score) in enumerate(ranked):
            name = s["name"][:40]
            if spd > 0:
                marker = Fore.GREEN + " ✓ BEST" if i == 0 else ""
                consecutive = get_consecutive_failures(s["name"])
                fail_info = f" [{consecutive} fails]" if consecutive > 0 else ""

                # Get stability from history
                with history_lock:
                    entries = config_history.get(s["name"], [])
                    successes = (
                        sum(1 for _, _, succ in entries if succ) if entries else 0
                    )
                    stability = f"{successes}/{len(entries)}" if entries else "0/0"

                print(
                    Fore.WHITE + f"  {i + 1:2d}. {name:<40} {spd:6.2f} MB/s  "
                    f"Score: {score:6.2f}  Stability: {stability}{fail_info}{marker}"
                )
            else:
                consecutive = get_consecutive_failures(s["name"])
                print(
                    Fore.RED
                    + f"  {i + 1:2d}. {name:<40} FAILED{' (consecutive: ' + str(consecutive) + ')' if consecutive else ''}"
                )

        if current_best:
            print(Fore.GREEN + f"\n  ► Active: {current_best}")

        print(Fore.YELLOW + f"\n  Full results shown for {display_duration}s...")

    def print_compact_view(remaining_seconds):
        clear_screen()
        print(Fore.CYAN + "=" * 60)
        print(Fore.CYAN + "  TOP 3 CONFIGS + COUNTDOWN")
        print(Fore.CYAN + "=" * 60)

        # Show only top 3 successful configs
        successful = [(s, spd, score) for s, spd, score in ranked if spd > 0]
        top3 = successful[:3]

        for i, (s, spd, score) in enumerate(top3):
            name = s["name"][:45]
            if i == 0 and name == current_best:
                print(
                    Fore.GREEN
                    + f"  #{i + 1} {name:<45} {spd:6.2f} MB/s  Score: {score:.2f} ★ ACTIVE"
                )
            else:
                color = Fore.YELLOW if i == 0 else Fore.WHITE
                print(
                    color + f"  #{i + 1} {name:<45} {spd:6.2f} MB/s  Score: {score:.2f}"
                )

        # Show countdown timer
        mins, secs = divmod(remaining_seconds, 60)
        hours, mins = divmod(mins, 60)
        time_str = (
            f"{hours:02d}:{mins:02d}:{secs:02d}" if hours else f"{mins:02d}:{secs:02d}"
        )

        print(Fore.CYAN + f"\n  ⏱ Next test in: {time_str}")

        # Simple progress bar
        bar_length = 30
        progress = (interval - remaining_seconds) / interval
        filled = int(bar_length * progress)
        bar = "█" * filled + "░" * (bar_length - filled)
        print(Fore.CYAN + f"  [{bar}]")

    # Show full results first
    print_full_results()
    time.sleep(display_duration)

    # Then switch to compact view with countdown
    remaining = interval - display_duration
    if remaining > 0:
        # Update display every second for the countdown
        for sec in range(remaining, 0, -1):
            print_compact_view(sec)
            time.sleep(1)

        # Final clear before new test cycle
        clear_screen()
    else:
        # If interval is shorter than display duration, just show compact briefly
        print_compact_view(remaining)
        time.sleep(max(1, remaining))


def should_switch(current_config_name, ranked_results):
    """
    Determine if we should switch to a new config using hysteresis.
    Only switch if the best config's score is significantly better than current's.
    """
    if not current_config_name or not ranked_results:
        return True

    best_server, best_speed, best_score = ranked_results[0]

    # If current is already the best, don't switch
    if best_server["name"] == current_config_name:
        return False

    # If best has failed, don't switch
    if best_speed == 0:
        return False

    # Find current config in results
    current_entry = next(
        (r for r in ranked_results if r[0]["name"] == current_config_name), None
    )

    if not current_entry:
        # Current config not found in results (shouldn't happen normally)
        return True

    _, current_speed, current_score = current_entry

    # Switch only if best score is significantly better
    # (best_score > current_score * (1 + SWITCH_THRESHOLD) or current has failed)
    if current_speed == 0:
        return True

    improvement = (
        (best_score - current_score) / current_score
        if current_score > 0
        else float("inf")
    )

    return improvement > SWITCH_THRESHOLD


# ── Entry point ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Xray speed-based proxy balancer with intelligent scoring",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  python3 balancer.py --dry-run\n"
            "  python3 balancer.py --interval 300\n"
            "  python3 balancer.py --configs /path/to/configs.txt\n"
            "  python3 balancer.py --port 1080"
        ),
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Test configs and print results, do not launch Xray",
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=CHECK_INTERVAL,
        help=f"Seconds between re-tests (default: {CHECK_INTERVAL})",
    )
    parser.add_argument(
        "--configs", type=str, default=CONFIGS_FILE, help="Path to configs.txt"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=SOCKS_PORT,
        help=f"SOCKS proxy port (default: {SOCKS_PORT})",
    )
    parser.add_argument(
        "--display-time",
        type=int,
        default=5,
        help="Seconds to show full results (default: 5)",
    )
    args = parser.parse_args()

    SOCKS_PORT = args.port
    servers = load_configs(args.configs)
    proc = None

    # Load existing history
    load_history()

    if args.dry_run:
        print(Fore.YELLOW + "=== DRY RUN — Xray will not be launched ===\n")
        ranked = run_tests(servers)
        print_results(ranked)
    else:
        try:
            current_best = None
            if os.path.exists(XRAY_CONFIG) and os.path.getsize(XRAY_CONFIG) > 0:
                print(Fore.GREEN + f"Xray config exists, starting xray---> ")
                proc = launch_xray(None, proc)
            else:
                print(
                    Fore.YELLOW
                    + "Xray config missing, will start xray after running test--->"
                )

            while True:
                print(Fore.YELLOW + "\n---------- Speed Test ----------")
                ranked = run_tests(servers, current_best)

                # Check if we should switch using hysteresis
                if should_switch(current_best, ranked):
                    best_server, best_speed, best_score = ranked[0]

                    if best_speed > 0:
                        print(Fore.GREEN + f"\nSwitching to {best_server['name']}...")
                        proc = launch_xray(best_server, proc)
                        current_best = best_server["name"]

                        # Show improvement details
                        if current_best:
                            old_entry = next(
                                (r for r in ranked if r[0]["name"] == current_best),
                                None,
                            )
                            if old_entry:
                                print(
                                    Fore.CYAN
                                    + f"  New score: {best_score:.2f} vs old: {old_entry[2]:.2f}"
                                )
                else:
                    best_server, best_speed, best_score = ranked[0]
                    if best_server["name"] == current_best:
                        print(
                            Fore.YELLOW
                            + f"\nKeeping current best: {current_best} (score: {best_score:.2f})"
                        )
                    else:
                        print(
                            Fore.YELLOW
                            + f"\nCurrent config {current_best} is still competitive, keeping it."
                        )

                # Save history periodically
                save_history()

                # Dynamic display with countdown
                print_dynamic_display(
                    ranked, current_best, args.interval, args.display_time
                )

        except KeyboardInterrupt:
            print(Fore.RED + "\n\nCTRL+C detected.")
            save_history()
            sys.exit(0)
