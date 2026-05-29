# xray-balancer

An intelligent, self-managing Xray proxy balancer. Tests a list of VLESS and Trojan configs by real download speed and latency, then automatically keeps the fastest one running as a LAN-accessible SOCKS5 proxy. Re-tests on a configurable interval and switches if a better config is found.

No dependency on v2rayN or any other GUI client.

## How it works

1. Reads configs from `configs.txt` — one URI per line, or subscription URLs
2. For each config, spins up a temporary Xray instance on a private port
3. Runs a two-stage test: health check (latency) → download speed test
4. Scores each config using a weighted combination of speed, latency, and historical stability
5. Launches a persistent Xray SOCKS5 proxy with the best config
6. Re-tests on a configurable interval; only switches if the improvement exceeds a threshold
7. Persists test history across restarts in `config_history.json`

## Requirements

- Python 3.9+
- `curl` (pre-installed on macOS and most Linux distros; download for Windows from [curl.se](https://curl.se/windows/))
- Xray binary (see setup below)

## Setup

**1. Clone the repo**
```bash
git clone https://github.com/yourname/xray-balancer.git
cd xray-balancer
```

**2. Install Python dependencies**
```bash
pip3 install -r requirements.txt
```

**3. Add the Xray binary**

Download the Xray binary for your platform from [XTLS/Xray-core releases](https://github.com/XTLS/Xray-core/releases) and place it in the project folder:

```bash
# macOS / Linux
cp /path/to/xray ./xray
chmod +x ./xray

# Windows: place xray.exe in the project folder
```

**4. Create `configs.txt`**

Add your proxy URIs one per line. Supports `vless://` and `trojan://` URIs and subscription URLs (plain-text or base64-encoded):

```
vless://uuid@host:port?...#name
trojan://password@host:port?...#name
https://your-subscription-url.com/sub
```

Empty lines are ignored. Any address/port in the URI is automatically normalized to `127.0.0.1:40443` in the generated Xray config.

## Usage

**Test all configs without launching Xray:**
```bash
python3 balancer.py --dry-run
```

**Run normally:**
```bash
python3 balancer.py
```

**Custom interval (e.g. every 5 minutes):**
```bash
python3 balancer.py --interval 300
```

**Custom SOCKS port:**
```bash
python3 balancer.py --port 1080
```

**Larger download test sample (more accurate, slower):**
```bash
python3 balancer.py --test-size 10
```

**Custom configs file:**
```bash
python3 balancer.py --configs /path/to/myconfigs.txt
```

**All options:**
```
--dry-run           Test all configs and show results, do not launch Xray
--interval N        Seconds between re-test cycles (default: 1800)
--port N            SOCKS5 proxy port (default: 4567)
--configs PATH      Path to configs file (default: configs.txt in script folder)
--test-size N       Download test size in MB (default: 1)
--display-time N    Seconds to show full results table before countdown (default: 5)
```

## Connecting other devices

Once running, configure any device on your LAN to use:
```
Protocol : SOCKS5
Host     : <your machine's LAN IP>
Port     : 4567  (or whatever --port you set)
```

To find your LAN IP:
```bash
# macOS / Linux
ip addr show   # or: ifconfig

# Windows
ipconfig
```

## Scoring system

Each config is scored using three weighted factors from its recent test history:

| Factor | Weight | Description |
|---|---|---|
| Speed | 40% | Average download speed across recent successful tests |
| Latency | 30% | Average round-trip time from health checks |
| Stability | 30% | Ratio of successful tests in the history window |

A switch only happens if the best candidate's score exceeds the current config's score by more than `SWITCH_THRESHOLD` (default: 20%). This prevents thrashing when two configs have similar performance.

Configs that fail repeatedly are subject to exponential backoff — they are skipped for increasing durations to avoid wasting time on dead servers.

## Supported protocols

| Protocol | Transports |
|---|---|
| `vless` | WebSocket, xHTTP, gRPC, HTTPUpgrade, SplitHTTP |
| `trojan` | WebSocket, xHTTP, gRPC, HTTPUpgrade, SplitHTTP |

TLS and REALITY security modes are supported. Flow control (`xtls-rprx-vision`) is supported for VLESS.

## Configuration constants

All tunable values are at the top of `balancer.py`:

| Constant | Default | Description |
|---|---|---|
| `SOCKS_PORT` | `4567` | SOCKS5 proxy port |
| `SOCKS_LISTEN` | `0.0.0.0` | Listen address (`0.0.0.0` = all interfaces) |
| `SNI_PORT` | `40443` | Upstream tunnel port |
| `TEST_URL` | Cloudflare 1MB | URL used for download speed test |
| `HEALTH_URL` | gstatic 204 | URL used for health/latency checks |
| `TEST_TIMEOUT` | `15` | Max seconds for download test |
| `HEALTH_TIMEOUT` | `5` | Max seconds for health check |
| `CHECK_INTERVAL` | `1800` | Seconds between re-test cycles |
| `BASE_TEST_PORT` | `19000` | Starting port for temporary test instances |
| `W_SPEED` | `0.4` | Weight for speed in scoring |
| `W_STABILITY` | `0.6` | Weight for stability in scoring |
| `SWITCH_THRESHOLD` | `0.2` | Minimum score improvement required to switch |
| `HISTORY_WINDOW` | `6` | Number of past results to consider for scoring |
| `DISPLAY_TOP_N_FULL` | `10` | Configs shown in full results view |
| `DISPLAY_TOP_N_COMPACT` | `3` | Configs shown during countdown |
| `PING_COUNT` | `3` | Number of pings averaged for latency |
| `XRAY_STARTUP_WAIT` | `2.0` | Seconds to wait after launching Xray |

## Files

| File | Description |
|---|---|
| `balancer.py` | Main script |
| `configs.txt` | Your proxy URIs (not committed) |
| `xray` / `xray.exe` | Xray binary (not committed) |
| `xrayconfig.json` | Generated active Xray config (not committed) |
| `config_history.json` | Persisted test history (not committed) |
| `balancer.log` | Runtime log (not committed) |

## Notes

- Press `Ctrl+C` to stop cleanly — Xray is always terminated on exit, including crashes
- `configs.txt`, the Xray binary, and all generated files are in `.gitignore` — never commit your configs
- On Windows, make sure `curl` is in your PATH
- Python 3.9 or newer is required (`tuple[bool, int]` type hint syntax)
