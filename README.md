# Surfshark AmneziaWG Studio (Anti-Censorship)

A complete desktop application with a clean, modern GUI built in **Python** & **Flet** specifically designed for users in restricted network environments (such as Iran) to automate extracting, resolving, testing, and generating **AmneziaWG** (obfuscated WireGuard) configuration files for Surfshark VPN.

---

## Key Architecture & Workflows

### Stage A: Initial Harvest & Profile Setup (On-Demand)
- **Attended Browser Automation (Playwright)**: Launches an interactive Chromium browser window where you log in to your Surfshark account (allowing you to solve 2FA, SMS verification, or CAPTCHA with 100% reliability).
- **Network Interception & DOM Scraping**: Automatically intercepts Surfshark backend cluster API responses and extracts:
  - User WireGuard configuration (`PrivateKey`, `Address`, `DNS`).
  - Full server cluster metadata (Continent, Country, City, Server `PublicKey`, Hostname, Port).
- **Local Blueprint Persistence**: Saves extracted metadata to `surfshark_servers.json` so you do **not** need to log in again for daily scans.
- **Offline / Manual Fallback**: Includes a built-in seed catalog of 30+ global Surfshark clusters and a file importer for existing `.conf` files.

### Stage B: Scanner, Validator & Config Generator (Daily / Frequent Execution)

> [!WARNING]
> **خاموش بودن VPN قبل از تست (Disconnect VPN Before Testing)**:
> برای کشف دقیق آی‌پی‌های باز و فیلترنشده در شبکه ایران، بسته‌های تست حتماً باید مستقیماً از ارائه‌دهنده اینترنت محلی (همراه اول، ایرانسل، مخابرات، شاتل و ...) ارسال شوند.
> اگر فیلترشکن دیگری (مانند ExpressVPN، v2ray، IranSplit و ...) در زمان اسکن روشن باشد، ترافیک تست از داخل سرور خارجی عبور کرده و نتایج کاملاً کاذب خواهند بود.
> این نرم‌افزار به صورت خودکار وضعیت اینترفیس پیش‌فرض شبکه (`utun`, `tun`, `tap`) را پایش کرده و در صورت فعال بودن VPN، هشدار بلادرنگ و تاییدیه قبل از اسکن نمایش می‌دهد.

1. **Active VPN Pre-Flight Detection**:
   - Analyzes default route (`netstat -rn`, `ip route`) to detect active virtual tunnels.
   - Shows live visual banner in the GUI (`⚠️ VPN روشن است` vs `🟢 شبکه مستقیم`).
   - Prompts with a confirmation modal before any scan begins.
2. **Smart DNS Resolution (Anti-Poisoning)**:
   - Completely bypasses the local operating system's DNS resolver to defeat ISP DNS hijacking/poisoning (such as fake `10.10.34.34` sinkholes in Iran).
   - Concurrently queries multiple encrypted DNS-over-HTTPS (DoH) providers: **Cloudflare** (`1.1.1.1`), **Google** (`8.8.8.8`), and **Quad9** (`9.9.9.9`).
   - Discovers **all** round-robin `A` records behind each hostname (e.g. `de-ber.prod.surfshark.com` -> 4 to 8 distinct IPs).
2. **High-Concurrency UDP 51820 Reachability Check**:
   - Concurrently tests UDP reachability and round-trip time (RTT) latency for port `51820` for every discovered raw IP.
   - Probes using syntactically valid 148-byte WireGuard Initiation packets.
   - Filters out dead or firewalled IPs, displaying live latency badges (`🟢 <150ms`, `🟡 <280ms`, `🔴 >280ms`).
3. **AmneziaWG Obfuscation Injection**:
   - Injects protocol obfuscation parameters into `[Interface]` to evade Deep Packet Inspection (DPI):
     ```ini
     Jc = 4
     Jmin = 50
     Jmax = 1000
     S1 = 0
     S2 = 0
     H1 = 1
     H2 = 2
     H3 = 3
     H4 = 4
     ```
   - Sets the `[Peer]` endpoint directly to the verified raw IP: `Endpoint = <RESOLVED_IP>:51820`.

---

## GUI Features

- **Control Center**:
  - `Update Server Metadata (Browser Login)`: Launches Chromium for profile synchronization.
  - `Scan & Test Working IPs`: Resolves DoH and performs concurrent UDP latency checks with an animated progress bar and live log stream.
  - `Export All Valid Configs (.zip)`: Bundles all verified reachable configs into a organized zip archive with per-country folders.
  - `Import .conf / JSON`: Offline importer for existing WireGuard files or blueprint databases.
- **Customizable Obfuscation Headers**:
  - Fine-tune `Jc`, `Jmin`, `Jmax`, `S1`, `S2`, `H1`, `H2`, `H3`, `H4`.
  - Built-in presets: *Iran Balanced*, *Iran Aggressive*, and *Standard WireGuard*.
- **Interactive Hierarchy Tree**:
  - Grouped by: **Continent > Country > City / Cluster > Working Raw IPs**.
  - Real-time search filter by country name, city, or IP.
- **Single Server Inspection**:
  - **Copy Config to Clipboard**: Instantly copy `.conf` content.
  - **Scannable QR Code**: Displayed directly in the desktop app for easy import into the AmneziaWG mobile app (iOS/Android).

---

## Installation & Quick Start

### 1. Automatic One-Click Launcher (macOS / Linux)
Open Terminal in this directory and run:
```bash
./run.sh
```
This automatically initializes a Python virtual environment, installs dependencies, and launches the desktop GUI.

### 2. Manual Setup
```bash
# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# (Optional, for Stage A browser login) Install Playwright browser
playwright install chromium

# Launch Desktop GUI
python3 main.py
```

### 3. Command Line (Headless / Automated Scan)
To run resolution and testing directly from the command line:
```bash
# Run CLI scan and automatically export working configs to ZIP:
python3 main.py --cli-scan --export-zip
```

### 4. Phone Version (Mobile UI on your local network)
Runs the same scanner with a phone-sized UI and does **not** depend on Shadowrocket (no `wg://` links, no Shadowrocket storage):
```bash
python3 main.py --mobile            # or: ./run.sh --mobile
python3 main.py --mobile --port 9000
```
1. The terminal prints a link like `http://<LAN-IP>:8550/?t=<token>`. Open it on the phone while it is on the same Wi-Fi or hotspot.
2. The token is required for every phone. Anyone who has the link can copy your WireGuard key, so do not share it. Restarting the app creates a new token.
3. The computer itself can open `http://127.0.0.1:8550/` without a token.

Phone screens:
- **Servers**: working IPs grouped by country. Each row has **copy** (one config) and **QR / text** (view the config and scan it). Check rows, or use "select whole country", then tap the selection button for:
  - **Copy queue**: copies one config at a time. The AmneziaWG app imports one config per paste, so tap *Next* after each import.
  - **Combined text**: all selected configs in one block, each with a numbered separator.
  - **Endpoint list**: `country - city | IP:port | latency` lines.
- **Scan**: DoH resolution plus UDP 51820 probing with a live log. Turn VPN off first.
- **Settings**: obfuscation preset, PrivateKey entry, and data reload.

Clipboard access in a phone browser over plain HTTP can be blocked by the browser. If copy does not work, open the config view and long-press the text to copy it manually.

---

## File Structure

- `main.py`: Application entrypoint (Desktop GUI or headless CLI scanner).
- `ui.py`: Flet-based desktop GUI with metrics, tree views, QR codes, and dialogs.
- `mobile_app.py`: Phone-sized Flet UI served with `--mobile` (no Shadowrocket integration).
- `mobile_core.py`: Flet-free logic for the phone version: config and group copy formats, copy queue, headless scan, and token check.
- `dns_resolver.py`: Anti-poisoning DoH multi-provider resolver and round-robin IP discovery.
- `checker.py`: Concurrent UDP port 51820 reachability and RTT latency checker.
- `config_builder.py`: AmneziaWG config generator, QR code encoder, and ZIP batch packager.
- `browser_harvest.py`: Attended Chromium automation for Surfshark login and API harvesting.
- `surfshark_servers.json`: Persistent blueprint containing credentials and cluster metadata.
- `requirements.txt`: Python package requirements (`flet`, `playwright`, `httpx`, `qrcode[pil]`, etc.).
- `run.sh`: Automated launcher script for macOS.
- `tests/test_amnezia.py`: Unit and integration test suite.
