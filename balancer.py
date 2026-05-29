import argparse
import asyncio
import atexit
import hashlib
import json
import logging
import os
import platform
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import zipfile
from collections import deque
from datetime import datetime
from logging.handlers import RotatingFileHandler

import aiohttp
import requests
from aiohttp_socks import ProxyConnector
from colorama import Fore, Style, init
from rich import box
from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.progress import BarColumn, Progress, TextColumn
from rich.table import Table
from rich.text import Text

LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "balancer.log")
LOG_MAX_MB = 5
LOG_BACKUPS = 3

handler = RotatingFileHandler(
    LOG_FILE,
    maxBytes=LOG_MAX_MB * 1024 * 1024,
    backupCount=LOG_BACKUPS,
    encoding="utf-8",
)
handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))

logger = logging.getLogger("balancer")
logger.setLevel(logging.INFO)
logger.addHandler(handler)

init(autoreset=True)

_xray_name = "xray.exe" if sys.platform == "win32" else "xray"
XRAY_REPO = "XTLS/Xray-core"
XRAY_API = f"https://api.github.com/repos/{XRAY_REPO}/releases/latest"
XRAY_VERSION_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), ".xray_version"
)
XRAY = os.path.join(os.path.dirname(os.path.abspath(__file__)), _xray_name)
CONFIGS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "configs.txt")
XRAY_CONFIG = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "xrayconfig.json"
)
HISTORY_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "config_history.json"
)
global SOCKS_PORT, SPEED_TEST_SIZE
SOCKS_PORT = 4567
SOCKS_LISTEN = "0.0.0.0"
SNI_PORT = 40443
BASE_TEST_PORT = 19000
TEST_URL = "https://speed.cloudflare.com/__down?bytes=1000000"
HEALTH_URL = "http://www.gstatic.com/generate_204"
TEST_TIMEOUT = 15
HEALTH_TIMEOUT = 5
CHECK_INTERVAL = 30 * 60

# ── Scoring system weights ─────────────────────────────────────────────────────
W_SPEED = 0.4
W_STABILITY = 0.6
SWITCH_THRESHOLD = 0.2
HISTORY_WINDOW = 6

# ── Smart testing thresholds ───────────────────────────────────────────────────
SPEED_TEST_SIZE = 1
MIN_HEALTHY_SPEED = 0.1

# ── Rich console for flicker-free display ──────────────────────────────────────
console = Console()

# ── Global state ───────────────────────────────────────────────────────────────
_active_proc = None
_active_config_name = None
config_history = {}
history_lock = threading.Lock()
display_state = {
    "ranked": [],
    "current_best": None,
    "interval": CHECK_INTERVAL,
    "cycle_start": time.time(),
    "test_complete": False,
}


def _set_active_proc(proc):
    global _active_proc
    _active_proc = proc


def _cleanup():
    if _active_proc and _active_proc.poll() is None:
        console.print("[yellow]\nStopping Xray...[/yellow]")
        _active_proc.terminate()
        try:
            _active_proc.wait(timeout=3)
        except Exception:
            _active_proc.kill()
        console.print("[green]Xray stopped.[/green]")
        logger.info("Cleanup triggered, stopping Xray")

    save_history()


atexit.register(_cleanup)

if sys.platform != "win32":

    def _sigterm_handler(signum, frame):
        sys.exit(0)

    signal.signal(signal.SIGTERM, _sigterm_handler)

# ── Xray check and update ─────────────────────────────────────────────────────────


def _get_xray_asset_name():
    system = sys.platform
    machine = platform.machine().lower()

    arch_map = {
        "x86_64": "64",
        "amd64": "64",
        "i386": "32",
        "i686": "32",
        "aarch64": "arm64-v8a",
        "arm64": "arm64-v8a",
        "armv7l": "arm32-v7a",
    }
    arch = arch_map.get(machine)
    if not arch:
        logger.error(f"Unsupported architecture: {machine}")
        console.print(f"[red]Unsupported architecture: {machine}[/red]")
        return None

    if system == "win32":
        return f"Xray-windows-{arch}.zip"
    elif system == "darwin":
        return f"Xray-macos-{arch}.zip"
    else:
        return f"Xray-linux-{arch}.zip"


def _get_latest_release_info():
    try:
        response = requests.get(XRAY_API, timeout=10)
        response.raise_for_status()
        data = response.json()
        return data["tag_name"], data["assets"]
    except Exception as e:
        logger.error(f"Failed to fetch Xray release info: {e}")
        console.print(f"[red]Failed to fetch Xray release info: {e}[/red]")
        return None, None


def _download_and_extract_xray(asset_url, asset_name):
    tmp_dir = tempfile.mkdtemp()
    zip_path = os.path.join(tmp_dir, asset_name)
    try:
        console.print(f"[cyan]Downloading {asset_name}...[/cyan]")
        logger.info(f"Downloading Xray from {asset_url}")

        with requests.get(asset_url, stream=True, timeout=60) as r:
            r.raise_for_status()
            total = int(r.headers.get("content-length", 0))
            downloaded = 0

            with open(zip_path, "wb") as f:
                for chunk in r.iter_content(chunk_size=8192):
                    f.write(chunk)
                    downloaded += len(chunk)
                    if total:
                        pct = downloaded / total * 100
                        print(f"\r  {pct:.1f}%", end="", flush=True)

        print()

        with zipfile.ZipFile(zip_path, "r") as z:
            z.extractall(tmp_dir)

        binary_name = "xray.exe" if sys.platform == "win32" else "xray"
        extracted_bin = os.path.join(tmp_dir, binary_name)

        if not os.path.exists(extracted_bin):
            logger.error("Xray binary not found inside zip")
            console.print("[red]Xray binary not found inside zip[/red]")
            return False

        shutil.move(extracted_bin, XRAY)

        if sys.platform != "win32":
            os.chmod(XRAY, 0o755)

        return True

    except Exception as e:
        logger.error(f"Download/extract failed: {e}")
        console.print(f"[red]Download failed: {e}[/red]")
        return False
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def ensure_xray(update=False):
    asset_name = _get_xray_asset_name()
    if not asset_name:
        sys.exit(1)

    latest_version, assets = _get_latest_release_info()
    if not latest_version:
        if not os.path.exists(XRAY):
            console.print("[red]No Xray binary and could not fetch release info.[/red]")
            sys.exit(1)
        logger.warning("Could not check for updates, using existing binary")
        return

    current_version = None
    if os.path.exists(XRAY_VERSION_FILE):
        with open(XRAY_VERSION_FILE, "r") as f:
            current_version = f.read().strip()

    xray_exists = os.path.exists(XRAY)

    if xray_exists and not update and current_version == latest_version:
        console.print(f"[green]Xray {current_version} is up to date.[/green]")
        return

    if xray_exists and not update:
        console.print(
            f"[green]Xray found (version unknown or unchecked). Use --update-xray to update.[/green]"
        )
        return

    if xray_exists and update and current_version == latest_version:
        console.print(
            f"[green]Xray is already the latest version ({latest_version}).[/green]"
        )
        return

    action = "Updating" if xray_exists else "Downloading"
    console.print(f"[cyan]{action} Xray {latest_version}...[/cyan]")
    logger.info(f"{action} Xray {latest_version}")

    asset = next((a for a in assets if a["name"] == asset_name), None)
    if not asset:
        console.print(
            f"[red]Asset {asset_name} not found in release {latest_version}[/red]"
        )
        logger.error(f"Asset {asset_name} not found in release {latest_version}")
        if not xray_exists:
            sys.exit(1)
        return

    success = _download_and_extract_xray(asset["browser_download_url"], asset_name)
    if success:
        with open(XRAY_VERSION_FILE, "w") as f:
            f.write(latest_version)
        console.print(f"[green]Xray {latest_version} ready.[/green]")
        logger.info(f"Xray {latest_version} installed successfully")
    else:
        if not xray_exists:
            sys.exit(1)


# ── History management ─────────────────────────────────────────────────────────


def load_history():
    global config_history
    if os.path.exists(HISTORY_FILE):
        try:
            with open(HISTORY_FILE, "r") as f:
                data = json.load(f)
                for name, entries in data.items():
                    config_history[name] = deque(
                        [
                            (e[0], e[1], e[2], int(e[3]) if len(e) > 3 else 0)
                            for e in entries
                        ],
                        maxlen=HISTORY_WINDOW,
                    )
        except Exception:
            pass


def save_history():
    with history_lock:
        serializable = {}
        for name, entries in config_history.items():
            serializable[name] = list(entries)
        try:
            with open(HISTORY_FILE, "w") as f:
                json.dump(serializable, f, indent=2)

            logger.info("History saved")
        except Exception as e:
            logger.error(f"Failed to save history: {e}")
            pass


def update_history(config_name, speed, success, latency=0):
    with history_lock:
        if config_name not in config_history:
            config_history[config_name] = deque(maxlen=HISTORY_WINDOW)
        config_history[config_name].append((time.time(), speed, success, latency))


def calculate_score(
    config_name: str,
    current_speed: float,
    current_latency: int = 0,
):
    with history_lock:
        if config_name not in config_history or len(config_history[config_name]) == 0:
            return current_speed

        entries = config_history[config_name]

        successes = sum(1 for _, _, success, _ in entries if success)

        stability_score = successes / len(entries)

        successful_entries = [
            (speed, lat) for _, speed, success, lat in entries if success
        ]

        if not successful_entries:
            return 0

        avg_speed = sum(s for s, _ in successful_entries) / len(successful_entries)

        avg_latency = sum(l for _, l in successful_entries) / len(successful_entries)

        speed_score = min(avg_speed / 20.0, 1.0)

        latency_score = max(0.0, 1.0 - (avg_latency / 1000.0))

        final_score = speed_score * 0.4 + latency_score * 0.3 + stability_score * 0.3

        return final_score


def get_consecutive_failures(config_name):
    with history_lock:
        if config_name not in config_history:
            return 0
        count = 0
        for _, _, success, _ in reversed(config_history[config_name]):
            if not success:
                count += 1
            else:
                break
        return count


def get_backoff_delay(config_name, base_delay=300):
    failures = get_consecutive_failures(config_name)
    if failures == 0:
        return 0
    return min(base_delay * (2 ** (failures - 1)), 3600)


def should_test_config(config_name, last_test_time):
    backoff = get_backoff_delay(config_name)
    if backoff == 0:
        return True
    time_since_last = time.time() - last_test_time if last_test_time else float("inf")
    return time_since_last >= backoff


# ── Unique name generation ─────────────────────────────────────────────────────


def generate_unique_name(uri, original_name=""):
    """
    Generate a unique name for each config using a hash of the URI.
    This prevents duplicate names from different configs.
    """
    # Create a short hash from the URI (first 8 chars of SHA256)
    uri_hash = hashlib.sha256(uri.encode()).hexdigest()[:8]

    if original_name and original_name != uri[:40]:
        # Use original name with hash suffix
        return f"{original_name}_{uri_hash}"
    else:
        # Use truncated URI with hash
        return f"{uri[:30]}_{uri_hash}"


# ── Parsers ────────────────────────────────────────────────────────────────────


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

    return stream


def parse_vless(uri, name):
    parsed = urllib.parse.urlparse(uri)
    params = dict(urllib.parse.parse_qsl(parsed.query))
    unique_name = generate_unique_name(uri, name)
    users = [{"id": parsed.username, "encryption": "none", "level": 0}]
    if params.get("flow"):
        users[0]["flow"] = params["flow"]
    return {
        "name": unique_name,
        "display_name": name,  # Keep original name for display
        "protocol": "vless",
        "settings": {
            "vnext": [
                {
                    "address": "127.0.0.1",
                    "port": SNI_PORT,
                    "users": users,
                }
            ]
        },
        "streamSettings": _build_stream(params),
    }


def parse_trojan(uri, name):
    parsed = urllib.parse.urlparse(uri)
    params = dict(urllib.parse.parse_qsl(parsed.query))
    unique_name = generate_unique_name(uri, name)
    return {
        "name": unique_name,
        "display_name": name,
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
    name = urllib.parse.unquote(fragment) if fragment else ""

    if uri.startswith("vless://"):
        return parse_vless(uri, name)
    if uri.startswith("trojan://"):
        return parse_trojan(uri, name)
    return None


# ── Config loading ─────────────────────────────────────────────────────────────


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
        console.print(f"[red]Failed to fetch subscription {url}: {e}[/red]")
        logger.error(f"Failed to fetch subscription {url}: {e}")
        return []


def load_configs(path):
    if not os.path.exists(path):
        console.print(f"[red]Error: configs file not found at {path}[/red]")
        logger.error(f"Error: configs file not found at {path}")
        sys.exit(1)

    servers = []
    skipped = 0

    with open(path, "r") as f:
        lines = [line.strip() for line in f if line.strip()]

    for line in lines:
        if line.startswith("http://") or line.startswith("https://"):
            console.print(f"[cyan]Fetching subscription: {line}[/cyan]")
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
        console.print(
            f"[yellow]Warning: {skipped} line(s) skipped (unsupported protocol)[/yellow]"
        )
        logger.warning(f"{skipped} line(s) skipped (unsupported protocol)")
    if not servers:
        console.print("[red]Error: no valid configs found[/red]")
        sys.exit(1)

    # Check for duplicate names
    names = [s["name"] for s in servers]
    unique_names = set(names)
    if len(names) != len(unique_names):
        console.print(
            f"[green]Generated {len(names)} unique config names (including {len(names) - len(unique_names)} deduplicated)[/green]"
        )

    console.print(f"[green]Loaded {len(servers)} configs\n[/green]")
    logger.info(f"Loaded {len(servers)} configs from {path}")
    time.sleep(2)
    return servers


# ── Xray process management ────────────────────────────────────────────────────


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
    global _active_config_name

    if current_proc and current_proc.poll() is None:
        current_proc.terminate()
        try:
            current_proc.wait(timeout=3)
        except Exception:
            current_proc.kill()
        time.sleep(2)

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
    logger.info(
        f"Launching Xray PID={proc.pid} config={server['name'] if server else 'existing'}"
    )
    _active_config_name = server["name"] if server else None

    time.sleep(2)

    if proc.poll() is not None:
        console.print(
            f"[red]✗ Xray failed to start! Exit code: {proc.returncode}[/red]"
        )
        logger.error(f"Xray failed to start, exit code: {proc.returncode}")
        return None

    return proc


# ── Smart two-stage testing ────────────────────────────────────────────────────


async def health_check(port: int) -> tuple[bool, int]:
    proxy_url = f"socks5://127.0.0.1:{port}"
    connector = None
    timeout = aiohttp.ClientTimeout(
        total=HEALTH_TIMEOUT,
        connect=3,
    )

    start = time.perf_counter()

    try:
        connector = ProxyConnector.from_url(proxy_url)
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
        ) as session:
            async with session.get(
                HEALTH_URL,
                allow_redirects=False,
            ) as response:
                latency_ms = int((time.perf_counter() - start) * 1000)

                success = response.status == 204

                return success, latency_ms

    except Exception:
        return False, 0

    finally:
        if not connector.closed:
            await connector.close()


async def _run_health_checks(port, count):
    results = []
    for _ in range(count):
        results.append(await health_check(port))
    return results


def measure_speed(port, test_size=None):
    if test_size is None:
        test_size = SPEED_TEST_SIZE
    try:
        size_mb = int(test_size)
        test_url = (
            f"https://speed.cloudflare.com/__down?bytes={size_mb}000000"
            if size_mb > 1
            else TEST_URL
        )

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
                test_url,
            ],
            capture_output=True,
            text=True,
            timeout=TEST_TIMEOUT + 3,
        )
        speed_bytes = float(result.stdout.strip())
        return speed_bytes / 1024 / 1024
    except:
        return 0.0


def test_server_smart(
    server, port, config_name, last_test_time, current_best=None
) -> tuple[float, int, bool]:
    if not should_test_config(config_name, last_test_time):
        backoff = get_backoff_delay(config_name)
        console.print(
            f"  [magenta]⊘ Skipping {config_name} (backoff: {backoff}s)[/magenta]"
        )
        logger.warning(f"Skipping {config_name} due to backoff ({backoff}s)")
        return 0.0, 0, False

    cfg = build_test_config(server, port)
    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
    json.dump(cfg, tmp)
    tmp.close()

    test_proc = subprocess.Popen(
        [XRAY, "run", "-c", tmp.name],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    time.sleep(1.5)

    if test_proc.poll() is not None:
        console.print(f"[red]✗ Xray test process failed for {config_name}[/red]")
        os.unlink(tmp.name)
        update_history(config_name, 0.0, False, 0)
        return 0.0, 0, False

    # Use display_name if available for prettier output
    display_name = server.get("display_name", config_name)
    console.print(f"  Testing [cyan]{display_name}[/cyan]...", end=" ")
    ping_num = 3
    checks = asyncio.run(_run_health_checks(port, ping_num + 1))
    healthy = checks[0][0]
    latency = sum(r[1] for r in checks[1:]) // ping_num if healthy else 0

    if not healthy:
        console.print("[red]✗ unhealthy[/red]")
        logger.warning(f"{config_name} unhealthy, skipping speed test")
        update_history(config_name, 0.0, False, latency)
        test_proc.terminate()
        try:
            test_proc.wait(timeout=3)
        except Exception:
            test_proc.kill()
        os.unlink(tmp.name)
        return 0.0, latency, False

    console.print(f"[blue]✓ healthy ({latency} ms)[/blue]", end=" ")
    speed = measure_speed(port)

    if speed > 0:
        console.print(f"[yellow]→ {speed:.2f} MB/s[/yellow]")
        logger.info(
            f"Testing {config_name}: speed={speed:.2f} MB/s latency={latency}ms"
        )
        update_history(config_name, speed, True, latency)
    else:
        console.print("[red]→ speed test failed[/red]")
        update_history(config_name, 0.0, False, latency)

    test_proc.terminate()
    try:
        test_proc.wait(timeout=3)
    except:
        test_proc.kill()
    os.unlink(tmp.name)
    time.sleep(0.5)

    return speed, latency, speed > 0


def run_tests_smart(servers, current_best=None):
    results = []
    current_time = time.time()

    if current_best:
        current_server = next((s for s in servers if s["name"] == current_best), None)
        if current_server:
            idx = servers.index(current_server)
            port = BASE_TEST_PORT + idx

            with history_lock:
                entries = config_history.get(current_best, [])
                last_test_time = entries[-1][0] if entries else 0

            console.print("[cyan]  → Testing current active config first:[/cyan]")
            speed, latency, success = test_server_smart(
                current_server, port, current_best, last_test_time, current_best
            )
            score = calculate_score(current_best, speed, latency) if success else 0
            results.append((current_server, speed, score, latency))

    for i, server in enumerate(servers):
        if current_best and server["name"] == current_best:
            continue

        port = BASE_TEST_PORT + i

        with history_lock:
            entries = config_history.get(server["name"], [])
            last_test_time = entries[-1][0] if entries else 0

        speed, latency, success = test_server_smart(
            server, port, server["name"], last_test_time
        )
        score = calculate_score(server["name"], speed, latency) if success else 0
        results.append((server, speed, score, latency))

    results.sort(key=lambda x: x[2], reverse=True)

    total_tested = len(results)
    healthy_count = sum(1 for _, speed, _, _ in results if speed > 0)
    console.print(
        f"[cyan]\n  Summary: {healthy_count}/{total_tested} configs healthy[/cyan]"
    )

    return results


# ── Rich TUI Display ───────────────────────────────────────────────────────────


def create_layout(ranked, current_best, interval, remaining_seconds=None):
    """Create the Rich layout for flicker-free display"""
    layout = Layout()
    layout.split_column(
        Layout(name="header", size=3),
        Layout(name="body"),
        Layout(name="footer", size=3),
    )

    # Header
    xray_status = get_xray_status_text()
    header_text = Text()
    header_text.append("SMART SPEED TEST RESULTS", style="bold cyan")
    if remaining_seconds is not None:
        mins, secs = divmod(remaining_seconds, 60)
        hours, mins = divmod(mins, 60)
        time_str = (
            f"{hours:02d}:{mins:02d}:{secs:02d}" if hours else f"{mins:02d}:{secs:02d}"
        )
        header_text.append(f"  ⏱ Next test: {time_str}", style="yellow")

    layout["header"].update(Panel(header_text, border_style="cyan"))

    # Body - Results table
    table = Table(box=box.ROUNDED, show_header=True, header_style="bold cyan")
    table.add_column("#", style="dim", width=4)
    table.add_column("Config Name", style="cyan", width=30)
    table.add_column(f"Speed\n{SPEED_TEST_SIZE}MB test", justify="center", width=12)
    table.add_column("Score", justify="center", width=8)
    table.add_column("Latency", justify="center", width=8)
    table.add_column("Stability", width=10)
    table.add_column("Status", width=15)

    successful = [(s, spd, score, lat) for s, spd, score, lat in ranked if spd > 0]
    top_show = 15  # Show top 10 in full view, or 3 in compact

    if remaining_seconds is not None:
        top_show = 7

    for i, (s, spd, score, lat) in enumerate(ranked[:top_show]):
        name = s.get("display_name", s["name"])[:28]

        if spd > 0:
            speed_str = f"{spd:.2f} MB/s"
            score_str = f"{score:.2f}"
            lat_str = f"{lat} ms"

            with history_lock:
                entries = config_history.get(s["name"], [])
                successes = (
                    sum(1 for _, _, succ, _ in entries if succ) if entries else 0
                )
                stability = f"{successes}/{len(entries)}" if entries else "0/0"

            consecutive = get_consecutive_failures(s["name"])

            if s["name"] == current_best:
                status = "[green]★ ACTIVE[/green]"
                style = "green"
            elif i == 0:
                status = "[yellow]★ BEST[/yellow]"
                style = "yellow"
            else:
                status = ""
                style = ""

            if consecutive > 0:
                status += f" [{consecutive} fails]"

            table.add_row(
                str(i + 1),
                name,
                speed_str,
                score_str,
                lat_str,
                stability,
                status,
                style=style,
            )
        else:
            consecutive = get_consecutive_failures(s["name"])
            backoff = get_backoff_delay(s["name"])
            status = f"FAILED ({consecutive})"
            if backoff > 0:
                status += f" [dim](backoff: {backoff}s)[/dim]"

            table.add_row(str(i + 1), name, "-", "-", "-", "-", status, style="red")

    layout["body"].update(Panel(table, title="Config Performance", border_style="blue"))

    # Footer
    footer_text = Text()
    xray_status, xray_color = get_xray_status_text()
    footer_text.append(xray_status, style=xray_color)

    if current_best:
        current_entry = next((r for r in ranked if r[0]["name"] == current_best), None)
        if current_entry:
            display_name = current_entry[0].get(
                "display_name", current_entry[0]["name"]
            )
            footer_text.append(f"  |  Active: {display_name}", style="green")

    layout["footer"].update(Panel(footer_text, border_style="cyan"))

    return layout


def get_xray_status_text():
    """Get Xray status as Rich text"""
    if not _active_proc:
        return "XRAY: NOT RUNNING", "red"
    elif _active_proc.poll() is None:
        pid = _active_proc.pid
        return f"XRAY: RUNNING [PID: {pid}]", "green"
    else:
        return f"XRAY: CRASHED (exit: {_active_proc.returncode})", "red"


def display_loop(
    ranked,
    current_best,
    interval,
    display_duration=5,
    proc_ref=None,
    last_server_ref=None,
):
    with Live(
        create_layout(ranked, current_best, interval),
        console=console,
        refresh_per_second=4,
        screen=True,
    ) as live:
        start_time = time.time()

        while time.time() - start_time < display_duration:
            live.update(create_layout(ranked, current_best, interval))
            time.sleep(0.25)

        remaining = interval - display_duration
        for sec in range(remaining, 0, -1):
            live.update(create_layout(ranked, current_best, interval, sec))

            if proc_ref and proc_ref[0] and proc_ref[0].poll() is not None:
                exit_code = proc_ref[0].returncode
                logger.error(
                    f"Xray crashed during wait (exit code: {exit_code}), relaunching..."
                )
                console.print(
                    f"[red]Xray crashed (exit: {exit_code}), relaunching...[/red]"
                )

                if last_server_ref and last_server_ref[0]:
                    new_proc = launch_xray(last_server_ref[0], None)
                    if new_proc:
                        proc_ref[0] = new_proc
                        logger.info(f"Xray relaunched, new PID={new_proc.pid}")
                    else:
                        logger.error("Relaunch failed")
                        console.print("[red]Relaunch failed.[/red]")

            time.sleep(1)


def should_switch(current_config_name, ranked_results):
    if not current_config_name or not ranked_results:
        return True

    best_server, best_speed, best_score, best_latency = ranked_results[0]

    if best_server["name"] == current_config_name:
        return False

    if best_speed == 0:
        return False

    current_entry = next(
        (r for r in ranked_results if r[0]["name"] == current_config_name), None
    )

    if not current_entry:
        return True

    _, current_speed, current_score, current_latency = current_entry

    if current_speed == 0:
        return True

    improvement = (
        (best_score - current_score) / current_score
        if current_score > 0
        else float("inf")
    )
    if improvement > SWITCH_THRESHOLD:
        logger.info(
            f"Switching from {current_config_name} to {ranked[0][0]['name']} (improvement: {improvement:.1%})"
        )
    else:
        logger.info(
            f"Keeping {current_config_name}, improvement {improvement:.1%} below threshold {SWITCH_THRESHOLD:.1%}"
        )

    return improvement > SWITCH_THRESHOLD


# ── Entry point ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Xray intelligent proxy balancer with smart testing and Rich TUI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  python3 balancer.py --dry-run\n"
            "  python3 balancer.py --interval 300\n"
            "  python3 balancer.py --configs /path/to/configs.txt\n"
            "  python3 balancer.py --port 1080 --test-size 10"
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
    parser.add_argument(
        "--test-size", type=int, default=1, help="Download test size in MB (default: 1)"
    )
    parser.add_argument(
        "--update-xray",
        action="store_true",
        help="Download or update Xray to the latest version",
    )
    args = parser.parse_args()

    SOCKS_PORT = args.port
    SPEED_TEST_SIZE = args.test_size

    ensure_xray(update=args.update_xray)
    if not os.path.exists(XRAY):
        console.print(f"[red]Error: Xray binary not found at {XRAY}[/red]")
        sys.exit(1)

    servers = load_configs(args.configs)
    proc = None

    load_history()

    if args.dry_run:
        console.print("[yellow]=== DRY RUN — Smart testing mode ===[/yellow]\n")
        ranked = run_tests_smart(servers)
        display_loop(ranked, None, 30, args.display_time)
    else:
        try:
            current_best = None
            if os.path.exists(XRAY_CONFIG) and os.path.getsize(XRAY_CONFIG) > 0:
                console.print("[green]Xray config exists, starting xray...[/green]")
                proc = launch_xray(None, proc)
            else:
                console.print(
                    "[yellow]Xray config missing, will start xray after running test...[/yellow]"
                )

            while True:
                console.print(
                    Panel(
                        "[bold yellow]SMART SPEED TEST CYCLE[/bold yellow]",
                        border_style="yellow",
                        width=50,
                    )
                )

                ranked = run_tests_smart(servers, current_best)

                if should_switch(current_best, ranked):
                    best_server, best_speed, best_score, best_latency = ranked[0]

                    if best_speed > 0:
                        old_best = current_best
                        display_name = best_server.get(
                            "display_name", best_server["name"]
                        )
                        console.print(
                            f"\n[green]✓ Switching to {display_name}...[/green]"
                        )
                        proc = launch_xray(best_server, proc)
                        if proc:
                            current_best = best_server["name"]

                            if old_best:
                                old_entry = next(
                                    (r for r in ranked if r[0]["name"] == old_best),
                                    None,
                                )
                                if old_entry:
                                    speed_diff = best_speed - old_entry[1]
                                    latency_diff = old_entry[3] - best_latency
                                    console.print(
                                        f"[cyan]  Speed: {speed_diff:+.2f} MB/s | Latency: {latency_diff:+.2f}s[/cyan]"
                                    )
                        else:
                            console.print("[red]Failed to launch new config![/red]")
                else:
                    best_server, best_speed, best_score, best_latency = ranked[0]
                    display_name = current_best
                    if current_best:
                        current_server = next(
                            (s for s in servers if s["name"] == current_best), None
                        )
                        if current_server:
                            display_name = current_server.get(
                                "display_name", current_best
                            )

                    if best_server["name"] == current_best:
                        console.print(
                            f"[yellow]\n✓ Keeping current best: {display_name} (score: {best_score:.2f})[/yellow]"
                        )
                    else:
                        console.print(
                            f"[yellow]\n✓ Current config {display_name} is still competitive[/yellow]"
                        )

                save_history()

                proc_ref = [proc]
                last_server_ref = [best_server]

                display_loop(
                    ranked,
                    current_best,
                    args.interval,
                    args.display_time,
                    proc_ref=proc_ref,
                    last_server_ref=last_server_ref,
                )

                proc = proc_ref[0]

        except KeyboardInterrupt:
            console.print("\n[red]CTRL+C detected.[/red]")
            # save_history()
            sys.exit(0)
