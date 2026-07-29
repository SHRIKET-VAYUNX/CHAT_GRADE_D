# VAYUNX Chat Application — Grade D

Secure chat application with end-to-end encryption, MFA, and SSO (OAuth/SAML).
Backend: FastAPI + PostgreSQL + Redis + MinIO. Frontend: React + Vite + TypeScript.

> **WARNING — this is the deliberately BROKEN / INSECURE / DEPRECATED crypto
> profile, for an authorized security course.** Every cryptographic primitive
> below (RSA-1024 / PKCS#1 v1.5 / MD5, AES-128-CBC with a *hardcoded* key and a
> *static IV* + HMAC-MD5, unsalted single-pass MD5 password hashing, RSA-1024
> key *transport* with no forward secrecy, SSLv3 transport, an *expired*
> self-signed cert, disabled cert validation, disabled HSTS, and a *seeded
> deterministic* RNG) is implemented **on purpose** and is intentionally
> vulnerable. Do **not** deploy this, and do not reuse any of its crypto in any
> real system. See `DECISIONS.md` for the full algorithm table and caveats.

Converted 2026-07-27 from a Grade C (classical/legacy-compliant) copy of this
project — only the cryptographic provider implementations (and the TLS/isolation
configuration) changed; business logic, API contracts, and database schema are
identical. This folder builds and runs **independently and concurrently** with
Grades A, B, and C (no Docker/Postgres/Redis/MinIO port or volume collisions).
See `DECISIONS.md` for the algorithm table and caveats, and `HANDOFF.md` for the
full Grade D conversion process (the per-file changes, isolation setup, and
verification results).

## Prerequisites

- Python 3.11 (backend requires `>=3.11,<3.12`)
- Node.js 18+ and npm
- Docker Desktop (for PostgreSQL, Redis, MinIO, Mailhog)
- OpenSSL (for local dev certs, optional)

## 1. Clone and configure environment

```bash
git clone <repo-url>
cd CHAT_Grade_D
cp .env.example .env
```

Edit `.env` and fill in values (DB/Redis/MinIO passwords, `MFA_SECRET_ENCRYPTION_KEY`,
etc.). Note: in Grade D the `MFA_SECRET_ENCRYPTION_KEY` is **ignored** — the
AES-128-CBC cipher uses a *hardcoded* key (kept only to satisfy the 16-byte
config validation). See `.env.example` comments for full setup instructions.

Google OAuth and SAML SSO are optional — leave those variables blank to disable
them.

## 2. Backend setup

Dependencies are declared in [`backend/pyproject.toml`](backend/pyproject.toml)
(source of truth) and mirrored in `backend/requirements.txt` for `pip`-based
installs (includes runtime + dev/test/lint tools).

```bash
cd backend
python -m venv .venv

# Windows
.venv\Scripts\activate
# macOS/Linux
source .venv/bin/activate

# Option A — editable install from pyproject.toml
pip install -e ".[dev]"

# Option B — requirements.txt
pip install -r requirements.txt
```

Run database migrations (requires Postgres up — see step 4):

```bash
alembic upgrade head
```

## 3. Frontend setup

```bash
cd frontend
npm install
```

## 4. Start infrastructure (Postgres, Redis, MinIO, Mailhog)

```bash
docker compose -f docker/docker-compose.yml --env-file .env up -d postgres redis minio mailhog
```

Create the MinIO dev bucket once (MinIO does not auto-create buckets):

```bash
docker exec vayunx-grade-d-minio-1 mc alias set local http://localhost:9000 \
  vayunx-storage local-dev-only-minio-password
docker exec vayunx-grade-d-minio-1 mc mb local/vayunx-files-grade-d
```

## 5. Run the app

### Option A — one-command dev launcher (recommended)

From the project root, with the backend venv already created (step 2):

```bash
python backend/run.py
```

This builds + starts the **full Docker stack** — infra (Postgres, Redis, MinIO,
MailHog) + the containerized backend, `arq` worker, frontend, and the **SSLv3
reverse proxy** on `https://localhost:8443` — and opens the app in **Pale Moon**.
Press `Ctrl+C` to stop the app containers (backend, worker, frontend,
reverse-proxy); Docker infra is left running (pass `--stop-docker` to also stop
it on exit).

> **Grade D transport — SSLv3 is the ONLY protocol, and it's enforced.** The
> backend (`:8000`) and frontend (`:80`) run **inside Docker** and are NOT
> published to the host (docker-compose uses `expose:`, not `ports:`). The only
> host-facing endpoint is the SSLv3 reverse proxy on `https://localhost:8443`
> (the custom nginx+OpenSSL-1.0.2u image) — uvicorn/Python cannot serve SSLv3
> itself (OpenSSL 3.x compiled it out). There is **no `:5174` and no `:8001` on
> the host**, so Chrome / Edge / Firefox / Brave have no plain-http port to fall
> back to — they removed SSLv3 post-POODLE, so the handshake fails (that failure
> *is* the expected Grade D outcome), which is why `run.py` opens the app in
> **Pale Moon** instead. To load it manually, use Pale Moon (enable
> `security.tls.version.min`/`ssl3` + RC4 in `about:config`) or
> `openssl s_client -ssl3 -cipher RC4-MD5 -connect localhost:8443`.

### Option B — run each service manually (native, NOT SSLv3-only)

If you need hot-reload and accept a plain-http backdoor (the native frontend at
`http://localhost:5174` IS reachable by Chrome/Edge, bypassing SSLv3), you can
run the services natively. This is NOT the SSLv3-only path — use Option A for
that.

```bash
# Terminal 1 — backend (plain http)
cd backend
.venv\Scripts\activate        # or: source .venv/bin/activate
uvicorn src.main:app --reload --host 127.0.0.1 --port 8001

# Terminal 2 — background worker (email delivery)
cd backend
.venv\Scripts\activate
python -m arq src.workers.worker_settings.WorkerSettings

# Terminal 3 — frontend (plain http)
cd frontend
npm run dev
```

This exposes `http://localhost:5174` and `http://127.0.0.1:8001` directly to
the host, so a modern browser CAN load the app over plain http — it bypasses
SSLv3. For the real Grade D SSLv3 transport with no backdoor, use Option A
(`python backend/run.py`), which containerizes the app so only `:8443` (SSLv3)
is published.

### Option C — full Docker stack manually (same as Option A, without the launcher)

```bash
docker compose -f docker/docker-compose.yml --env-file .env up --build
```

This is exactly what `python backend/run.py` (Option A) does under the hood —
the full containerized stack, served via the SSLv3 reverse proxy at
`https://localhost:8443`. Note: a bare `up` also starts the unused
`reverse-proxy-dev` service, which collides with `reverse-proxy` on port 8443 —
prefer Option A (which lists services explicitly) or `up` only the services you
need. The reverse proxy is a **custom image**
(`docker/reverse-proxy.Dockerfile`: nginx 1.22 built against OpenSSL 1.0.2u)
because stock `nginx:*-alpine` (OpenSSL 3.x) compiles SSLv3/RC4 out and cannot
serve the Grade D transport profile. The proxy offers **SSLv3** (SSLv3-only) +
RC4-MD5/DES cipher suites and **genuinely negotiates** SSLv3 with an
era-appropriate client (OpenSSL 1.0.2 `openssl s_client -ssl3 -cipher RC4-MD5`).
**Modern browsers (Edge/Chrome/Firefox) cannot connect** — they removed SSLv3
from their TLS stack entirely post-POODLE; this is the expected Grade D outcome.
See `DECISIONS.md`.

## Running tests

```bash
# Backend
cd backend
pytest

# Frontend
cd frontend
npm test
```

## Useful ports (Grade D — isolated from Grades A/B/C)

| Service        | Host port | Container port |
|----------------|-----------|----------------|
| Frontend (Vite)| 5174      | —              |
| Backend (API)  | 8001      | —              |
| PostgreSQL     | 5435      | 5432           |
| Redis          | 6380      | 6379           |
| MinIO API      | 9002      | 9000           |
| MinIO Console  | 9003      | 9001           |
| Mailhog SMTP   | 1026      | 1025           |
| Mailhog Web UI | 8026      | 8025           |
| Reverse proxy (TLS)  | 8443 | 443            |
| Reverse proxy (http) | 8080 | 80             |

Docker Compose project name: `vayunx-grade-d`. Postgres volume:
`postgres_data_grade_d`. MinIO volume: `minio_data_grade_d`. Postgres DB:
`vayunx_grade_d`. MinIO bucket: `vayunx-files-grade-d`.