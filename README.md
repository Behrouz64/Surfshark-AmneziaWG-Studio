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
Run these one at a time from the project folder:
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 main.py
```
Optional, only for the Stage A browser login: after activating the venv, run `playwright install chromium`.

### 3. Command Line (Headless / Automated Scan)
To run resolution and testing directly from the command line, and export the working configs as a ZIP:
```bash
python3 main.py --cli-scan --export-zip
```

### 4. Run the Tests on a Mac (Python 3.11)
The tests use Python 3.11 and the pinned `flet==0.28.3` from `requirements.txt`. Flet 1.x changed APIs the desktop UI relies on, so do not upgrade it.

Paste the commands one line at a time. Do not paste lines that start with `#`: zsh (the default macOS shell) runs them as commands and prints errors.

First, get the code on the branch. If the folder does not exist yet:
```bash
git clone -b claude/dreamy-archimedes-sv1bcc https://github.com/Behrouz64/Surfshark-AmneziaWG-Studio
cd Surfshark-AmneziaWG-Studio
```
If the folder already exists, go into it and update it:
```bash
cd Surfshark-AmneziaWG-Studio
git pull
```
Check that you are in the right place. The first command must print `claude/dreamy-archimedes-sv1bcc`:
```bash
git branch --show-current
```
Install Python 3.11 once, then run the tests:
```bash
brew install python@3.11
./scripts/mac_test.sh
```
The last line must report `OK` with a non-zero test count (about 110). The tests write only to temp folders and never read or change Shadowrocket.

If you prefer to run the steps by hand from the project folder:
```bash
python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m unittest -v
```

### 5. Phone Version (Mobile UI on your local network)
Runs the same scanner with a phone-sized UI. It never controls Shadowrocket (no Shadowrocket storage, no app control), but it copies `wg://` links that you paste into Shadowrocket on iPhone. Both copy formats are always available:
Start it with:
```bash
python3 main.py --mobile
```
`./run.sh --mobile` does the same and creates the venv first. To use another port, add `--port 9000`.
1. The terminal prints a link like `http://<LAN-IP>:8550/?t=<token>`. Open it on the phone while it is on the same Wi-Fi or hotspot.
2. The token is required for every visitor, including this computer. Anyone who has the link can copy your WireGuard key, so do not share it. Restarting the app creates a new token.
3. The page uses plain HTTP, so use it only on your home Wi-Fi or your own hotspot, never on public Wi-Fi.

Phone screens:
- **Servers**: working IPs grouped by country. Each row has **copy** (AmneziaWG config), **link** (`wg://` for Shadowrocket) and **QR / text** (view the config and scan it). Check rows, or use "select whole country", then tap the selection button for:
  - **Copy queue**: copies one config (or one `wg://` link) at a time. The AmneziaWG app imports one config per paste, and Shadowrocket takes one link per paste, so tap *Next* after each import.
  - **Combined text**: all selected configs in one block, each with a numbered separator.
  - **wg:// links**: all selected links, one per line (the same format as the desktop "Copy wg:// Links").
  - **Endpoint list**: `country - city | IP:port | latency` lines.
- **Scan**: DoH resolution plus UDP 51820 probing with a live log. Turn VPN off first.
- **Guide**: step-by-step instructions in Persian and English, covering both copy formats, group copy, testing in a real client, key safety and common problems.
- **Settings**: obfuscation preset, PrivateKey entry and data reload. The PrivateKey is kept in memory only: it is never written to disk by the phone UI, so enter it again after a restart.

Clipboard access in a phone browser over plain HTTP can be blocked by the browser. If copy does not work, open the config view and long-press the text to copy it manually.

---

### 5a. Terminal Version (no browser)
The same logic as the phone app, in the terminal. It works on the Mac with no browser and no network page:
```bash
.venv/bin/python phone_cli.py
```
The menu has the same steps: enter the PrivateKey (hidden, kept only in memory), scan, filter by continent and search, select servers, copy AmneziaWG configs and `wg://` links (group or single), the one-by-one copy queue, a QR code drawn with text blocks, and the guide. On a Mac the copy goes to the clipboard with `pbcopy`. Elsewhere the text is printed.

To check the copy text through the real macOS clipboard, without the browser:
```bash
.venv/bin/python scripts/mac_copy_check.py
```
It copies a group of links, reads them back, and checks each line against the reference format. It writes the links to `copy_check_links.txt`, which is git-ignored and contains the PrivateKey. Delete it after the test.

---

### 6. iPhone App (unsigned IPA)
The phone version can also run on the iPhone itself, without a computer. The app scans from the iPhone's own connection.

**Build the IPA on GitHub (no Mac needed for this step):**
1. Make a commit whose message starts with `[build]` (for example `[build] Test the phone copy`) and push the branch. Normal pushes do not start a build.
2. In the Actions tab, open the run **Build iOS IPA (unsigned)** for that commit. When it is green, download the artifact `surfshark-ios-unsigned` (it contains `SurfsharkAmneziaWG-unsigned.ipa`).

**Install it with a free Apple ID (Sideloadly, on a Mac or Windows PC):**
1. Install Sideloadly, connect the iPhone with a cable, and trust the computer on the phone.
2. Drag the `.ipa` into Sideloadly and enter your Apple ID. Sideloadly signs the app with it.
3. On the iPhone, enable **Settings → Privacy & Security → Developer Mode** (iOS 16 and later), then restart.
4. Open **Settings → General → VPN & Device Management**, and trust the developer profile.

**Limits of a free Apple ID:** the signature expires after 7 days. Sideloadly's Auto Refresh re-signs it while the computer and the phone are on the same network. After that, install the IPA again. The app is not on the App Store.

**Differences from the computer version:**
- Copying configs and `wg://` links works on the phone, and the QR code is drawn on screen, so you can scan it from the same phone or another device.
- The VPN is not detected automatically on iOS. Turn the VPN off yourself before the scan.
- The PrivateKey is kept in memory only, so enter it again after the app restarts.

**Building locally on a Mac** (needs Xcode): run `python3 scripts/sync_phone.py`, then `cd phone` and `flet build ipa -v`. The archive appears under `phone/build/ipa`.

Before publishing, change `org` in `phone/pyproject.toml` to your own reverse-domain name. It becomes part of the bundle ID.

---

## File Structure

- `main.py`: Application entrypoint (Desktop GUI or headless CLI scanner).
- `ui.py`: Flet-based desktop GUI with metrics, tree views, QR codes, and dialogs.
- `mobile_app.py`: Phone-sized Flet UI served with `--mobile` (no Shadowrocket integration).
- `mobile_core.py`: Flet-free logic for the phone version: config, `wg://` link and group copy formats, copy queue, headless scan, and token check.
- `mobile_guide.py`: the phone guide text in Persian and English, with a parity check that the two languages have the same structure.
- `phone_cli.py`: the phone version in the terminal (same logic as the phone app, no browser).
- `scripts/mac_copy_check.py`: checks the group copy text through the macOS clipboard, without a browser.
- `scripts/mac_test.sh`: creates a Python 3.11 venv and runs the test suite (macOS).
- `dns_resolver.py`: Anti-poisoning DoH multi-provider resolver and round-robin IP discovery.
- `checker.py`: Concurrent UDP port 51820 reachability and RTT latency checker.
- `config_builder.py`: AmneziaWG config generator, QR code encoder, and ZIP batch packager.
- `browser_harvest.py`: Attended Chromium automation for Surfshark login and API harvesting.
- `surfshark_servers.json`: Persistent blueprint containing credentials and cluster metadata.
- `requirements.txt`: Python package requirements (`flet`, `playwright`, `httpx`, `qrcode[pil]`, etc.).
- `run.sh`: Automated launcher script for macOS.
- `tests/test_amnezia.py`: Unit and integration test suite.
