"""One-command launcher for VAYUNX (Grade D — SSLv3 is the ONLY transport).

`python backend/run.py` brings up the FULL Docker stack — infra (Postgres,
Redis, MinIO, MailHog) + the containerized backend, arq worker, frontend, and
the SSLv3 reverse proxy — and opens the app in Pale Moon at
https://localhost:8443.

Why the full stack (not native uvicorn/vite): the backend and frontend run
INSIDE Docker and are NOT published to the host (docker-compose uses `expose:`,
not `ports:`). The only host-facing endpoint is the reverse proxy on :8443,
which speaks SSLv3. There is no :5174 and no :8001 on the host, so Chrome / Edge
/ Firefox / Brave CANNOT reach the app — they removed SSLv3 post-POODLE and the
plain-http ports simply don't exist to be bypassed. That is the only-SSLv3
guarantee. Pale Moon (or `openssl s_client -ssl3 -cipher RC4-MD5`) is how you
actually load it.

Usage (from anywhere):
    python backend/run.py
    (or, from inside backend/):  python run.py

Ctrl+C stops the app containers (backend, worker, frontend, reverse-proxy).
The infra containers are left running (cheap to leave up, slow to reprovision)
— pass --stop-docker to tear them down on exit too.

Flags:
    --no-browser     Don't auto-open Pale Moon; just print the URL + the
                     openssl s_client handshake command.
    --stop-docker    Also stop the infra containers on Ctrl+C.
"""

from __future__ import annotations

import argparse
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
ROOT_DIR = BACKEND_DIR.parent
COMPOSE_FILE = ROOT_DIR / "docker" / "docker-compose.yml"
ENV_FILE = ROOT_DIR / ".env"

# The ONLY host-facing endpoint. The reverse proxy speaks SSLv3 (custom
# nginx+OpenSSL-1.0.2u image) and fronts the containerized backend (:8000) +
# frontend (:80), which are NOT published to the host — so there is no
# plain-http :5174 / :8001 for a modern browser to bypass SSLv3 with.
PROXY_HOST, PROXY_PORT = "localhost", 8443
PROXY_URL = f"https://{PROXY_HOST}:{PROXY_PORT}"

# MailHog's web inbox — Grade D's isolated ports: 1026 (SMTP) + 8026 (web UI),
# matching docker/docker-compose.yml. Auto-opened alongside the app so the
# email-verification token is one click away on launch (dev mail is caught by
# MailHog, never delivered to a real inbox). It is plain http, so Pale Moon (or
# any browser) loads it fine.
MAILHOG_WEB_HOST, MAILHOG_WEB_PORT = "127.0.0.1", 8026
MAILHOG_WEB_URL = f"http://{MAILHOG_WEB_HOST}:{MAILHOG_WEB_PORT}"

# Pale Moon is the only browser launched — it still negotiates SSLv3 + RC4-MD5.
# Chrome/Edge/Firefox/Brave all removed SSLv3 post-POODLE and would fail the
# handshake, so they are deliberately never targeted.
PALEMOON_CANDIDATES = [
    r"C:\Program Files\Pale Moon\palemoon.exe",
    r"C:\Program Files (x86)\Pale Moon\palemoon.exe",
]

# Infra = data/queue services (left running on Ctrl+C unless --stop-docker).
# App = the request-serving layer (always stopped on Ctrl+C). reverse-proxy-dev
# is deliberately NOT started — it's the native-process-fronting variant; the
# full stack uses `reverse-proxy` (containerized backend/frontend) instead.
INFRA_SERVICES = ["postgres", "redis", "minio", "mailhog"]
APP_SERVICES = ["backend", "worker", "frontend", "reverse-proxy"]
ALL_SERVICES = INFRA_SERVICES + APP_SERVICES


def wait_for_port(host: str, port: int, timeout: float, label: str) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=1):
                return True
        except OSError:
            time.sleep(1)
    print(f"[run.py] Timed out waiting for {label} on {host}:{port}")
    return False


def compose(*args: str, capture: bool = False, check: bool = True) -> subprocess.CompletedProcess:
    # encoding/errors: docker build/up output is UTF-8 and contains bytes that
    # Windows' default cp1252 codec can't decode (e.g. 0x81), which crashes the
    # capture reader thread with UnicodeDecodeError. Decode as UTF-8 and replace
    # anything unmappable so capture never crashes (and error output still prints).
    return subprocess.run(
        ["docker", "compose", "-f", str(COMPOSE_FILE), "--env-file", str(ENV_FILE), *args],
        cwd=ROOT_DIR,
        capture_output=capture,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=check,
    )


def bring_up_stack() -> bool:
    """Build + start the full stack (infra + containerized app + reverse proxy).

    `--build` rebuilds the backend/frontend/reverse-proxy images on first run
    (the reverse-proxy image builds nginx against OpenSSL 1.0.2u — be patient).
    Services are listed explicitly so the unused `reverse-proxy-dev` service is
    never started (it would collide with `reverse-proxy` on port 8443).
    """
    print("[run.py] Building + starting the full Docker stack "
          "(infra, backend, worker, frontend, SSLv3 reverse proxy)...")
    print("[run.py]   (first run builds the nginx+OpenSSL-1.0.2u image — be patient)")
    result = compose("up", "-d", "--build", *ALL_SERVICES, capture=True, check=False)
    if result.returncode != 0:
        print("[run.py] ERROR bringing up the stack:")
        print(result.stdout)
        print(result.stderr)
        print("[run.py]   (port 8443 may already be in use — stop any leftover stack: "
              "`docker compose -f docker/docker-compose.yml stop`)")
        return False
    # `up` streams nothing under capture when already-built; surface any warnings.
    if result.stderr.strip():
        print(result.stderr.rstrip())
    return True


def find_palemoon() -> str | None:
    """Locate the Pale Moon executable (the only browser that speaks SSLv3)."""
    for candidate in PALEMOON_CANDIDATES:
        if Path(candidate).exists():
            return candidate
    return shutil.which("palemoon")


def open_in_palemoon(url: str) -> bool:
    """Open `url` in Pale Moon. Returns False if Pale Moon is not installed —
    in which case the caller prints the URL + handshake command instead. We
    NEVER fall back to the default browser (Chrome/Edge/Firefox/Brave), because
    they cannot complete the SSLv3 handshake.
    """
    exe = find_palemoon()
    if not exe:
        return False
    try:
        subprocess.Popen([exe, url])
        return True
    except OSError:
        return False


def print_ssl3_instructions() -> None:
    """How to actually load the SSLv3 app when Pale Moon isn't available."""
    print(f"[run.py] Pale Moon was not found. Install Pale Moon, then open:")
    print(f"[run.py]   {PROXY_URL}")
    print("[run.py] In Pale Moon's about:config, enable SSLv3 + RC4-MD5:")
    print("[run.py]   set security.tls.version.min = 0 and enable the ssl3 + rc4_md5 ciphers.")
    print("[run.py] Or test the handshake from a terminal:")
    print("[run.py]   openssl s_client -ssl3 -cipher RC4-MD5 -connect localhost:8443")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stop-docker", action="store_true",
                         help="Stop the infra containers on exit (Ctrl+C) too.")
    parser.add_argument("--no-browser", action="store_true",
                         help="Don't auto-open Pale Moon; just print the URL + "
                              "the openssl s_client handshake command.")
    args = parser.parse_args()

    if not bring_up_stack():
        sys.exit(1)

    # The reverse proxy listens on :8443 even though a modern browser's SSLv3
    # handshake then fails — so a port check confirms the stack is up, not that
    # Chrome can connect (it can't, by design).
    if not wait_for_port(PROXY_HOST, PROXY_PORT, 120, "SSLv3 reverse proxy"):
        print("[run.py] SSLv3 reverse proxy did not report a listener; check the logs above.")
        sys.exit(1)

    print("[run.py] SSLv3 transport is live on https://localhost:8443.")
    print("[run.py] Chrome/Edge/Firefox/Brave will FAIL to open it (SSLv3 removed "
          "post-POODLE) — that is the expected Grade D outcome.")
    print("[run.py] The app's internal http ports (:5174 / :8001) are NOT published to "
          "the host, so there is no plain-http backdoor — only SSLv3 on :8443.")

    if not args.no_browser:
        if open_in_palemoon(PROXY_URL):
            print(f"[run.py] Opened {PROXY_URL} in Pale Moon.")
        else:
            print("[run.py] Pale Moon not found — not opening any other browser "
                  "(Chrome/Edge/Firefox/Brave can't speak SSLv3).")
            print_ssl3_instructions()
        # Open the MailHog inbox too so the verification email is one click away.
        # It's plain http, so Pale Moon loads it.
        time.sleep(0.5)
        if open_in_palemoon(MAILHOG_WEB_URL):
            print(f"[run.py] Opened MailHog inbox {MAILHOG_WEB_URL} in Pale Moon.")
        else:
            print(f"[run.py] MailHog inbox (plain http): {MAILHOG_WEB_URL}")
    else:
        print_ssl3_instructions()

    print("[run.py] Running. Press Ctrl+C to stop the app containers "
          "(backend, worker, frontend, reverse-proxy).")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[run.py] Stopping the app containers...")
    finally:
        compose("stop", *APP_SERVICES, capture=True, check=False)
        print("[run.py] App containers stopped "
              "(backend, worker, frontend, reverse-proxy).")

        if args.stop_docker:
            print("[run.py] Stopping Docker infra...")
            compose("stop", *INFRA_SERVICES, capture=True, check=False)
            print("[run.py] Infra stopped.")


if __name__ == "__main__":
    main()