# End-to-End Setup on a Fresh Ubuntu Machine (Polymarket ↔ Kalshi Arb)

This guide assumes a completely fresh Ubuntu 22.04+ machine and walks you from nothing → live arb trading:

- Build the C++ arb watcher (`arb_ws_watcher`)
- Install Python + dependencies
- Configure Polymarket & Kalshi keys
- Generate `live_sports_matches.csv`
- Run the arb watcher with both legs live

> **Note:** Adjust paths and keys to your actual values. Commands are designed to be copy–paste friendly.

---

## 1. System packages

```bash
sudo apt update
sudo apt upgrade -y

sudo apt install -y \
  build-essential \
  cmake \
  git \
  pkg-config \
  libssl-dev \
  zlib1g-dev \
  python3 \
  python3-venv \
  python3-pip \
  curl \
  wget \
  ca-certificates
```

---

## 2. Get the repo onto the box

Pick a base dir and clone/copy the repo:

```bash
mkdir -p ~/projects
cd ~/projects

git clone <YOUR_GIT_URL> Prediction-Exploits
cd Prediction-Exploits
```

For the rest of this guide we assume:

```bash
REPO=~/projects/Prediction-Exploits
cd "$REPO"
```

You should see at least:

- `CMakeLists.txt`
- `src/main.cpp`
- `find_live_sports_matches.py`
- `pm_place_order.py`

---

## 3. Build the C++ arb watcher (`arb_ws_watcher`)

```bash
cd "$REPO"

mkdir -p build
cd build

cmake ..
cmake --build .
```

You should end up with:

```bash
ls "$REPO"/build
# arb_ws_watcher  CMakeFiles  ...
```

If you see OpenSSL link errors, make sure `libssl-dev` is installed (included in step 1).

---

## 4. Python environment & dependencies

We’ll use a project-local virtualenv.

### 4.1 Create and activate venv

```bash
cd "$REPO"

python3 -m venv .venv
source .venv/bin/activate

which python
# should be .../Prediction-Exploits/.venv/bin/python
```

### 4.2 Install required packages

```bash
pip install --upgrade pip

pip install \
  requests \
  pandas \
  cryptography \
  py_clob_client \
  py_order_utils
```

Optional (nice for debugging):

```bash
pip install ipython
```

> Remember: in any new shell, run `source .venv/bin/activate` before using the Python tools.

---

## 5. Keys & secrets

You need:

- A **Polymarket** private key (Ethereum key for Polygon), hex string.
- A **Kalshi** API key and matching **RSA private key** in PEM format.

### 5.1 Polymarket key

On the Ubuntu box:

```bash
mkdir -p ~/secrets
chmod 700 ~/secrets

nano ~/secrets/pmkey.txt
```

Paste your Polymarket private key (without quotes). If it doesn’t start with `0x`, `pm_place_order.py` will prepend it.

Secure it:

```bash
chmod 600 ~/secrets/pmkey.txt
```

Recommended env var for tools that read `PM_PK_PATH`:

```bash
echo 'export PM_PK_PATH="$HOME/secrets/pmkey.txt"' >> ~/.bashrc
source ~/.bashrc
```

### 5.2 Kalshi RSA key

Copy your PEM file from your Mac (example):

```bash
scp /path/on/mac/Testing5.txt \
    <ubuntu-user>@<ubuntu-host>:~/secrets/kalshi_rsa.pem
```

On Ubuntu:

```bash
chmod 600 ~/secrets/kalshi_rsa.pem
```

The file should look like:

```text
-----BEGIN RSA PRIVATE KEY-----
...
-----END RSA PRIVATE KEY-----
```

### 5.3 Kalshi API key

Use your known working key (example from logs):

```text
2e1883a0-61ad-472f-a5d5-9a89d87b4089
```

You’ll pass this to both the Python matcher and the C++ watcher via `--kalshi-key`.

---

## 6. Generate `live_sports_matches.csv` (Python matcher)

`find_live_sports_matches.py` queries Polymarket + Kalshi and produces a CSV of matched markets.

### 6.1 Activate venv

```bash
cd "$REPO"
source .venv/bin/activate
```

### 6.2 Run matcher

```bash
python find_live_sports_matches.py \
  --out live_sports_matches.csv \
  --tol-hours 72 \
  --debug \
  --kalshi-key "2e1883a0-61ad-472f-a5d5-9a89d87b4089" \
  --kalshi-private-key "$HOME/secrets/kalshi_rsa.pem"
```

Expected debug output (shape, not exact numbers):

```text
[Polymarket] fetching Sports + NCAA via tags…
[Kalshi] sports series total: ... | single-game filtered: ...
[Kalshi] {series}: markets fetched ...
[Kalshi] unique event tickers (GAME markets): ...
[Kalshi] game events w/ pair codes from markets: ...
[Match] total matches: N
✅ Wrote N matches to live_sports_matches.csv
```

If `N == 0`, discovery needs tuning, but the infrastructure is fine as long as the call succeeds and writes a CSV.

---

## 7. Polymarket order helper sanity check

The C++ arb watcher shells out to `pm_place_order.py` to execute PM orders. Make sure it runs correctly first.

### 7.1 Confirm CLI

```bash
cd "$REPO"
source .venv/bin/activate

python ./pm_place_order.py --help
```

You should see flags like:

- `--token-id`
- `--side {buy,sell}`
- `--price`
- `--size`
- `--tif {GTC,IOC,FOK}`
- `--pk-path`
- `--dry-run`

### 7.2 Dry-run a PM order

Pick a YES token ID from `live_sports_matches.csv` (column `pm_yes_token`). Then:

```bash
python ./pm_place_order.py \
  --token-id '<YES_TOKEN_ID>' \
  --side sell \
  --price 0.33 \
  --size 1 \
  --tif IOC \
  --pk-path "$HOME/secrets/pmkey.txt" \
  --dry-run
```

Expected:

- Prints `DEBUG OrderArgs: {...}` and `DRY RUN. Order args: ...`.
- Exit code 0.

If this works, the arb watcher’s PM leg will also work (it calls the same script with the same flags).

---

## 8. Optional: Kalshi auth sanity check (Python)

If you have the `kalshi_place_order.py` tool, you can double-check the key/PEM pair.

Example (adjust ticker):

```bash
cd "$REPO"
source .venv/bin/activate

python kalshi_place_order.py \
  --key-id "2e1883a0-61ad-472f-a5d5-9a89d87b4089" \
  --pem "$HOME/secrets/kalshi_rsa.pem" \
  --ticker "KXNBAGAME-25DEC22DALNOP-NOP" \
  --side yes \
  --action buy \
  --count 1 \
  --price 33 \
  --tif immediate_or_cancel \
  --safe-auth-test \
  --debug
```

You want a 2xx response and no `INCORRECT_API_KEY_SIGNATURE` errors.

> This step is optional: the C++ watcher already uses the same signing logic that your working Python tool uses.

---

## 9. Run the arb watcher (both legs live)

At this point you should have:

- `arb_ws_watcher` built in `build/`
- `live_sports_matches.csv` with at least one row
- Valid PM + Kalshi keys and Python env

### 9.1 Full run (both Polymarket + Kalshi)

From the repo root:

```bash
cd "$REPO"

./build/arb_ws_watcher \
  --csv live_sports_matches.csv \
  --row 1 \
  --pm-ws wss://ws-subscriptions-clob.polymarket.com/ws/market \
  --kalshi-ws wss://api.elections.kalshi.com/trade-api/ws/v2 \
  --pm-fee-bps 200 \
  --kalshi-fee-bps 100 \
  --min-edge-bps 50 \
  --stale-ms 15000 \
  --max-skew-ms 15000 \
  --ping-ms 2000 \
  --windows-csv arbs_windows.csv \
  --kalshi-key "2e1883a0-61ad-472f-a5d5-9a89d87b4089" \
  --kalshi-secret-path "$HOME/secrets/kalshi_rsa.pem" \
  --pm-exec "./pm_place_order.py" \
  --pm-pk-path "$HOME/secrets/pmkey.txt" \
  --verbose
```

You should see:

- Startup:

  ```text
  [EXEC] exec_kalshi=true exec_polymarket=true
  [KX] Private key loaded successfully from ...
  [PM] Hydrated tokens: yes=..., no=...
  ```

- WebSocket connections:

  ```text
  [PM] trying endpoint wss://ws-subscriptions-clob.polymarket.com/ws/market
  [KX] trying endpoint wss://api.elections.kalshi.com/trade-api/ws/v2
  [PM] connected ...
  [KX] connected ...
  ```

- Quotes streaming in:

  ```text
  [PM-POLLER] REST applied: bb=... ba=...
  [KX] SNAP payload: {...}
  [KX] DELTA payload: {...}
  ```

- Arbitrage detection and execution:

  ```text
  [ARB-CAND][PM->KX] raw=... bps=... sell_net=... buy_gross=...
  [ARB-OPEN] PM->KX sell@... buy@... bps_capital=...
  [FIRE-PM] placed sell order via pm_client: price=... qty=1 ok=1
  [FIRE-KX] placed KX order: ticker=... side=buy price=... qty=1 ok=1
  ```

To stop, press ENTER in the `arb_ws_watcher` terminal.

### 9.2 One-side-only modes (for testing)

- **Kalshi-only** (no PM orders):

  ```bash
  ./build/arb_ws_watcher ... --only-kalshi ...
  ```

- **Polymarket-only** (no KX orders):

  ```bash
  ./build/arb_ws_watcher ... --only-polymarket ...
  ```

Both modes still use quotes from both sides to **detect** arbs, but only execute the chosen leg.

---

## 10. Optional helper script

You can add a tiny wrapper script to simplify running a specific row:

```bash
cat > "$REPO/run_arb.sh" << 'EOF'
#!/usr/bin/env bash
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

cd "$REPO"

ROW="${1:-1}"

./build/arb_ws_watcher \
  --csv live_sports_matches.csv \
  --row "$ROW" \
  --pm-ws wss://ws-subscriptions-clob.polymarket.com/ws/market \
  --kalshi-ws wss://api.elections.kalshi.com/trade-api/ws/v2 \
  --pm-fee-bps 200 \
  --kalshi-fee-bps 100 \
  --min-edge-bps 50 \
  --stale-ms 15000 \
  --max-skew-ms 15000 \
  --ping-ms 2000 \
  --windows-csv arbs_windows.csv \
  --kalshi-key "2e1883a0-61ad-472f-a5d5-9a89d87b4089" \
  --kalshi-secret-path "$HOME/secrets/kalshi_rsa.pem" \
  --pm-exec "./pm_place_order.py" \
  --pm-pk-path "$HOME/secrets/pmkey.txt" \
  --verbose
EOF

chmod +x "$REPO/run_arb.sh"
```

Then run:

```bash
cd "$REPO"
./run_arb.sh 1      # row 1 from live_sports_matches.csv
./run_arb.sh 1818   # row 1818, etc.
```

---

## 11. Summary

On a completely fresh Ubuntu machine, the essential steps are:

1. Install system deps (`build-essential`, `cmake`, `python3-venv`, `libssl-dev`, ...).
2. Clone the repo and `cmake --build` to get `arb_ws_watcher`.
3. Create `.venv` and `pip install` Python deps.
4. Install Polymarket + Kalshi secrets under `~/secrets/`.
5. Run `find_live_sports_matches.py` to build `live_sports_matches.csv`.
6. Test `pm_place_order.py` with `--dry-run`.
7. Run `arb_ws_watcher` with the appropriate CLI flags.

Once this is set up, you can reuse the machine by:

```bash
cd ~/projects/Prediction-Exploits
source .venv/bin/activate
python find_live_sports_matches.py ...   # refresh matches
./run_arb.sh <row>
```

