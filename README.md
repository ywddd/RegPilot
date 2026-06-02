# RegPilot

RegPilot is a Python 3.11+ runner for account registration, OAuth callback handling, token exchange, account archiving, and optional callback submission into CPA.

## Current Status

The current implementation includes the full registration chain used by this project:

1. `/api/accounts/authorize`
2. `/api/accounts/user/register`
3. `/api/accounts/email-otp/send`
4. `/api/accounts/email-otp/validate`
5. `/api/accounts/create_account`
6. `platform.openai.com/auth/callback -> oauth/token`

Implemented capabilities:

- PKCE and authorization session setup
- Runtime environment profile selection: proxy, UA, language, timezone, viewport
- Temporary mailbox creation and OTP polling
- Registration submit, email OTP, about-you submit, account creation
- OAuth callback extraction and token exchange
- CLI and FastAPI management API
- Account persistence in `data/accounts.db`
- Result persistence in `data/last_result.json`
- CPA callback submission and account import helpers
- Existing account reauthorization with email OTP and optional phone verification
- Account inspection for CPA Codex auth files:
  - probes Codex usage through the CPA management `/api-call` endpoint
  - suggests enabling disabled accounts when weekly quota is available
  - suggests disabling accounts when weekly quota is exhausted
  - reauthorizes 401 accounts automatically, with the reauthorization step serialized to reduce risk-control pressure
  - marks accounts that require manual phone second verification as pending deletion
  - supports one-click execution of suggested CPA actions

## Installation

RegPilot supports Python 3.11+ on Windows, Linux, and macOS. Python 3.12 is recommended because the Docker image and current runtime use it.

### Requirements

- Python 3.11 or newer
- Git
- Network access to the configured mail/SMS/CPA services
- Optional: Docker and Docker Compose for container deployment

### Windows PowerShell

```powershell
git clone https://github.com/ywddd/RegPilot.git
cd RegPilot

py -3.12 -m venv .venv-win
.\.venv-win\Scripts\Activate.ps1
python -m pip install --upgrade pip setuptools wheel
python -m pip install -e .
```

Start the API:

```powershell
$env:REGPILOT_HOST="0.0.0.0"
$env:REGPILOT_PORT="8766"
python -m regpilot.api --host $env:REGPILOT_HOST --port $env:REGPILOT_PORT
```

Run checks on Windows:

```powershell
$env:PYTHONPATH="src"
.\.venv-win\Scripts\python.exe -m compileall -q src tests
.\.venv-win\Scripts\python.exe -m unittest discover -s tests -p "test*.py"
```

If PowerShell blocks venv activation, run:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

Then open a new PowerShell window and activate the virtual environment again.

### Linux

```bash
git clone https://github.com/ywddd/RegPilot.git
cd RegPilot

python3.12 -m venv .venv-linux312 || python3 -m venv .venv-linux
source .venv-linux312/bin/activate 2>/dev/null || source .venv-linux/bin/activate
python -m pip install --upgrade pip setuptools wheel
python -m pip install -e .
```

Start the API:

```bash
REGPILOT_HOST=0.0.0.0 REGPILOT_PORT=8766 python -m regpilot.api --host 0.0.0.0 --port 8766
```

Or use the bundled scripts:

```bash
scripts/api.sh
scripts/manage-api.sh start
scripts/manage-api.sh status
```

### macOS

Install Python with Homebrew if needed:

```bash
brew install python@3.12 git
```

Then install RegPilot:

```bash
git clone https://github.com/ywddd/RegPilot.git
cd RegPilot

python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip setuptools wheel
python -m pip install -e .
```

Start the API:

```bash
REGPILOT_HOST=0.0.0.0 REGPILOT_PORT=8766 python -m regpilot.api --host 0.0.0.0 --port 8766
```

### Development Install

For development/test tools:

```bash
python -m pip install -e '.[dev]'
```

Run the full check script on Linux/macOS:

```bash
scripts/check.sh
```

### Docker Compose

Docker is the simplest production-style install. Runtime data is stored in `./data` and logs in `./logs`; both are ignored by Git.

```bash
git clone https://github.com/ywddd/RegPilot.git
cd RegPilot

mkdir -p data logs
docker compose up -d --build
```

Check status:

```bash
docker compose ps
curl http://127.0.0.1:8766/api/health
```

Open the WebUI:

```text
http://127.0.0.1:8766/
```

To use a different port:

```bash
REGPILOT_PORT=8877 docker compose up -d --build
```

When changing environment variables or source files in Docker, rebuild/recreate the container:

```bash
docker compose up -d --build
```

If both compose files are present, prefer the explicit YAML file used by the current deployment:

```bash
docker compose -f docker-compose.yaml up -d --build
docker compose -f docker-compose.yaml ps
```

### Upgrade

For a Python virtual environment install:

```bash
git pull
source .venv/bin/activate
python -m pip install -e .
```

On Windows:

```powershell
git pull
.\.venv-win\Scripts\Activate.ps1
python -m pip install -e .
```

For Docker:

```bash
git pull
docker compose -f docker-compose.yaml up -d --build
```

### Runtime Files

These paths are runtime state and should not be committed:

- `data/`
- `logs/`
- `reports/`
- `backups/`
- `.env`

## CLI Usage

Run one registration task:

```bash
regpilot register --config /path/to/config.json
```

Override proxy directly:

```bash
regpilot register --config /path/to/config.json --proxy 'socks5://user:pass@host:port'
```

## FastAPI Management API

```bash
scripts/api.sh
```

Managed background mode:

```bash
scripts/manage-api.sh start
scripts/manage-api.sh status
```

The API scripts support these environment variables:

- `REGPILOT_HOME`: project directory, defaults to the parent of `scripts/`
- `REGPILOT_HOST`: bind host, defaults to `0.0.0.0`
- `REGPILOT_PORT`: bind port, defaults to `8766`
- `PYTHON_BIN`: Python executable, defaults to `python3`
- `REGPILOT_VENV`: virtual environment directory; defaults to `.venv-linux312`, `.venv-linux`, `.venv_linux`, then `.venv`

## WebUI Workflows

Open the WebUI at:

```text
http://127.0.0.1:8766/
```

Main pages:

- Account registration: configure proxy, mailbox, SMS provider, CPA address, and CPA management key; start registration and phone-binding jobs.
- Account pool: manage stored accounts, batch reauthorize, delete, and export account tokens.
- Account inspection: inspect CPA Codex auth files with the registration-page CPA settings, review only accounts that need action, and execute suggested enable/disable/delete operations.
- Unified logs: inspect job output across registration, reauthorization, phone binding, and account inspection.

Account inspection notes:

- The inspection page reads the CPA address, CPA management key, and CPA OAuth proxy from the registration configuration.
- The thread count controls CPA usage probing concurrency.
- CPA usage probing uses `https://chatgpt.com/backend-api/wham/usage` through the CPA management `/api-call` endpoint.
- If a CPA auth file returns 401 and a matching local account exists, RegPilot attempts automatic reauthorization.
- Reauthorization is serialized during inspection even when probing uses multiple threads. This keeps the feature automatic while avoiding multiple simultaneous OpenAI authorization flows.
- Accounts that still require manual phone second verification after reauthorization are marked pending deletion.
- Deleting a CPA auth file from the inspection page also deletes the matching local account from the RegPilot account pool when an account id is available.
- One-click suggested actions show a final execution summary and hide successfully processed rows from the current inspection list.

## Config Example

CPA settings use the existing `codex2api_*` config keys for compatibility with the running WebUI and stored config.

```json
{
  "proxy": "socks5://user:pass@host:port",
  "mail": {
    "request_timeout": 30,
    "wait_timeout": 60,
    "wait_interval": 2,
    "providers": [
      {
        "type": "cloudflare-temp-email",
        "base_url": "https://apimail.example.com",
        "admin_auth": "REPLACE_ME",
        "domain": "example.com"
      },
      {
        "type": "hotmail-api",
        "base_url": "http://127.0.0.1:17373"
      }
    ]
  }
}
```

Mail providers are tried in order. If a configured provider fails during mailbox creation, RegPilot tries the next provider.

## Output

Successful or failed CLI runs print a JSON summary and save the full result to:

- `data/last_result.json`

Common fields:

- `email`
- `password`
- `access_token`
- `refresh_token`
- `id_token`
- `mailbox`
- `callback_url`
- `error`

## Check

Run local syntax and unit checks:

```bash
scripts/check.sh
```

On Windows without Bash, use:

```powershell
$env:PYTHONPATH="src"
.venv\Scripts\python.exe -m compileall -q src tests
.venv\Scripts\python.exe -m unittest discover -s tests -p "test*.py"
```

## Notes

- Proxy quality is a key variable for registration success.
- `data/` and `logs/` contain runtime data and are intentionally ignored by Git.
- Treat `data/last_result.json`, account database files, API keys, and tokens as sensitive.
