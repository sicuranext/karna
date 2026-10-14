# syntax=docker/dockerfile:1
# Karna Console API (FastAPI). Base image pinned by digest; Python packages
# installed only if they match the hashes in requirements.txt.
FROM python:3.12-slim@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1 AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir --require-hashes --no-deps -r requirements.txt

COPY app.py auth.py store.py kong_connection.py ai_profiles.py assistant_runtime.py assistant_tools.py egress.py ./

# The public Karna skill (.claude/skills/karna in the repository), passed by
# compose as the "skills" build context: the assistant always works from the
# skill of the Karna version it ships with.
COPY --from=skills . /app/skills/karna/

# Run as a non-root user whose uid matches the Kong/openresty worker that owns
# the shared audit-log volume (1001). The ingester consumes (deletes) each
# audit file after storing it, which needs write on Kong's log directory — so
# the consumer must run as that directory's owner. /data is chowned to the same
# uid so the SQLite store + auth state stay writable on a fresh volume.
RUN useradd --system --uid 1001 --no-create-home karna 2>/dev/null || true \
    && mkdir -p /data && chown 1001:1001 /data
USER 1001:1001

EXPOSE 8080
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8080", "--no-server-header"]
