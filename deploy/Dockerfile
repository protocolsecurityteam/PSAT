FROM node:22-alpine AS site-builder

WORKDIR /site

COPY site/package.json site/package-lock.json ./
RUN npm ci

COPY site/ ./
RUN npm run build


FROM python:3.10-slim AS backend

# Surfaced via /api/version for post-deploy smoke checks. CI passes
# --build-arg GIT_SHA=<commit>; local builds default to "unknown".
ARG GIT_SHA=unknown
ENV GIT_SHA=${GIT_SHA}

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/root/.foundry/bin:/app/.venv/bin:${PATH}"

RUN apt-get update && apt-get install -y --no-install-recommends \
    bash \
    ca-certificates \
    curl \
    git \
    nodejs \
    && rm -rf /var/lib/apt/lists/*

RUN curl -L https://foundry.paradigm.xyz | bash \
    && /root/.foundry/bin/foundryup

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /app

COPY pyproject.toml uv.lock .python-version ./
RUN uv sync --frozen --no-dev

# Vyper compiler binary on PATH so crytic-compile (used by Slither for *.vy)
# can shell out. Pinned to 0.3.10: 0.4.x has an upstream crytic-compile bug
# (platform/vyper.py:101 splits a dict that the new sourceMap format returns).
RUN uv pip install "vyper==0.3.10"

# Playwright browsers + OS deps (required by dapp_crawl_worker). ~400MB.
RUN uv run --no-sync playwright install --with-deps chromium

# Runtime attestation calls solc --version before workers claim jobs. An empty
# solc-select cache makes that command download "latest", racing across workers
# and exceeding the startup timeout. Match CI's default compiler at build time.
# Invoke directly, as start_workers.sh does: uv run uses a different cache root.
RUN .venv/bin/solc-select install 0.8.27 \
    && .venv/bin/solc-select use 0.8.27 \
    && .venv/bin/solc --version

COPY api.py serve.py alembic.ini ./
COPY alembic/ alembic/
COPY db/ db/
COPY workers/ workers/
COPY deploy/start_workers.sh deploy/start_container.sh deploy/start_web.sh deploy/start_browser.sh deploy/start_monitor.sh deploy/
RUN chmod +x deploy/start_workers.sh deploy/start_container.sh deploy/start_web.sh deploy/start_browser.sh deploy/start_monitor.sh
COPY services/ services/
COPY schemas/ schemas/
COPY routers/ routers/
COPY utils/ utils/
COPY --from=site-builder /site/dist /app/site/dist

EXPOSE 8000

CMD ["./deploy/start_container.sh"]
