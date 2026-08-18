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

COPY api.py serve.py alembic.ini ./
COPY alembic/ alembic/
COPY db/ db/
COPY workers/ workers/
COPY start_workers.sh start_container.sh start_web.sh start_browser.sh start_monitor.sh ./
RUN chmod +x start_workers.sh start_container.sh start_web.sh start_browser.sh start_monitor.sh
COPY services/ services/
COPY schemas/ schemas/
COPY routers/ routers/
COPY utils/ utils/
COPY --from=site-builder /site/dist /app/site/dist

EXPOSE 8000

CMD ["./start_container.sh"]
