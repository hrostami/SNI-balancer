# SNI-Balancer

An intelligent Xray config balancer for SNI-spoofing environments.

SNI-Balancer continuously benchmarks VLESS and Trojan configs using real latency and download speed tests, scores them based on performance history and stability, then automatically keeps the best config running through Xray as a LAN-accessible SOCKS5 proxy.

Designed for censorship-heavy networks where SNI spoofing is required.

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
- Live Rich TUI dashboard
- Subscription URL support
- REALITY support
- TLS support
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

# Requirements

- Python 3.9+
- `curl`
- Internet access
- SNI-spoofing backend
