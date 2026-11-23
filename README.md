# Metin2 TR Clientless Market Search

English · [Türkçe](README.tr.md)

Python tools for connecting to Metin2 TR without running the game client and processing market data. The repository includes the Gameforge session flow, CH1 server selection, world login, market-search components, and offline tests. It does not include a website, market datasets, or personal session records.

**Collect your own data. Build your own tools.**

## Setup on Windows

You need Python 3.11 or newer, a local Gameforge installation, and Microsoft Edge or Google Chrome. If neither browser is installed, use Playwright Chromium.

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

Install Playwright Chromium only if needed:

```powershell
.\.venv\Scripts\python.exe -m playwright install chromium
```

## Run

Open `Clientless-Baslat.cmd` or run:

```powershell
.\.venv\Scripts\python.exe tools\start_clientless.py
```

On the first run, sign in with Gameforge, choose a Metin2 account and server, and confirm the character returned by the server. The launcher currently supports entry with the first character slot only. Use `--choose-server` to pick a different server for the current run.

The standard launcher does not require Frida. The optional one-off market search requires a local decoded search record. The Linux market worker requires a prepared local session file. Neither input is bundled.

## Offline tests

```powershell
.\.venv\Scripts\python.exe -B -m unittest discover -s tools -p 'selftest_*.py'
```

## Account and session data

Before using this project on live servers, check the game's terms. Keep local profiles, credentials, session files, and diagnostic logs private. The standard launcher does not write raw packet captures; diagnostics can include sensitive session data. Local runtime artifacts are excluded by `.gitignore`.

## Contact

Discord: `vervooo`
