# SNI-Balancer
<img width="1464" height="891" alt="Dashboard" src="https://github.com/user-attachments/assets/2374b29d-a258-48e0-81af-7bd827018dee" />

An intelligent Xray config balancer for SNI-spoofing method.

SNI-Balancer continuously benchmarks VLESS and Trojan configs using real latency and download speed tests, scores them based on performance history and stability, then automatically keeps the best config running through Xray as a LAN-accessible SOCKS5 proxy.

No GUI clients required. No manual switching. Fully automated.

---

# Features

- Automatic Xray download and update
- Automatic SNI-spoofing binary management
- Supports both Rust and Go SNI-spoofing backends
- Real-world speed testing through actual proxy traffic
- Latency-aware scoring system
- Historical stability tracking
- Exponential backoff for dead configs
- Automatic failover and recovery
- Live dashboard
- Subscription URL support
- Cross-platform:
  - Linux
  - Windows
  - macOS

---

# How It Works

1. Reads configs from `configs.txt`
2. Starts temporary isolated Xray instances for testing
3. Performs:
   - health checks
   - latency measurement
   - real download speed tests
4. Calculates a weighted score using:
   - speed
   - latency
   - historical stability
5. Launches the highest-scoring config
6. Continuously re-tests configs at configurable intervals
7. Automatically switches only when improvement exceeds a threshold
8. Persists history across restarts

---

# Supported Protocols

| Protocol | Supported Transports |
|---|---|
| VLESS | WS, gRPC, xHTTP, HTTPUpgrade, SplitHTTP |
| Trojan | WS, gRPC, xHTTP, HTTPUpgrade, SplitHTTP |


---

# Requirements

- Python 3.9+
- `curl`
- Internet access
- SNI-spoofing backend

---

# Installation

## Clone the repository

```bash
git clone https://github.com/hrostami/SNI-balancer.git
cd SNI-balancer
```

## Install dependencies

```bash
pip install -r requirements.txt
```

## Create `configs.txt`

Supports:
- `vless://`
- `trojan://`
- Subscription URLs
- Base64 subscriptions

Example:

```text
vless://uuid@host:port?...#MyConfig
trojan://password@host:port?...#Server2
https://subscription-url.example/sub
```

---

# Running

## Normal mode

```bash
python3 balancer.py
```

## Dry-run mode

Tests all configs without launching the final Xray instance.

```bash
python3 balancer.py --dry-run
```

## Custom interval

```bash
python3 balancer.py --interval 300
```

## Custom SOCKS5 port

```bash
python3 balancer.py --port 1080
```

## Larger speed test

```bash
python3 balancer.py --test-size 10
```

## Update Xray

```bash
python3 balancer.py --update-xray
```

---

# Command Line Options

| Argument | Description |
|---|---|
| `--dry-run` | Test configs only |
| `--interval` | Seconds between test cycles |
| `--configs` | Custom configs file |
| `--port` | SOCKS5 listen port |
| `--display-time` | Full dashboard display duration |
| `--test-size` | Download test size in MB |
| `--update-xray` | Download/update Xray |
| `--sni-variant` | `rust` or `go` |
| `--sni-connect` | Upstream address for SNI spoofing |
| `--sni-fake` | Fake SNI hostname |

---

# SNI Spoofing

This project requires an external SNI-spoofing process.

Supported implementations:
- Rust backend
- Go backend

If the binary is missing, SNI-Balancer can automatically download it.

Default values:

```text
Connect Address: 104.19.229.21:443
Fake SNI: hcaptcha.com
```

---

# Scoring System

Each config receives a weighted score:

| Metric | Weight |
|---|---|
| Speed | 40% |
| Stability | 30% |
| Latency | 30% |

The balancer avoids unnecessary switching by requiring a minimum improvement threshold before changing the active config.

Repeated failures trigger exponential backoff to avoid wasting resources on dead servers.

---

# Generated Files

| File | Description |
|---|---|
| `xrayconfig.json` | Active Xray config |
| `config_history.json` | Historical benchmark data |
| `balancer.log` | Runtime logs |
| `.xray_version` | Installed Xray version |

---

# Notes

- The SOCKS5 proxy listens on all interfaces by default (`0.0.0.0`)
- Temporary Xray instances are created during testing
- Dead configs are skipped intelligently using exponential backoff
- Xray is automatically relaunched if it crashes
- Duplicate config names are automatically deduplicated
- All generated files should remain ignored in Git

---

# Disclaimer

This project is intended for educational and research purposes.

Use responsibly and comply with local laws and regulations.
