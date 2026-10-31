FROM python:3.12-slim

WORKDIR /app

# Tesseract enables OCR of image-based phishing (threadline/ocr.py).
RUN apt-get update \
    && apt-get install -y --no-install-recommends tesseract-ocr \
    && rm -rf /var/lib/apt/lists/*

# Layer-cache the dependencies separately from the app code.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# `pip install playwright` only installs the Python bindings -- the browser
# itself is a separate download, and without it every sandbox detonation
# fails at launch. --with-deps pulls the shared libraries headless Chromium
# needs on a slim image.
#
# It costs roughly 400 MB and several minutes of build time, which is wasted
# on a host that can't run it anyway: Chromium needs about a gigabyte of RAM
# to start, so on a 512 MB free tier the browser would only ever OOM. Build
# with --build-arg INSTALL_BROWSER=false there (and set REPORTIT_SANDBOX=off)
# for a small, fast image without link detonation.
ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright
ARG INSTALL_BROWSER=true
RUN if [ "$INSTALL_BROWSER" = "true" ]; then \
        playwright install --with-deps chromium \
        && chmod -R a+rX /ms-playwright; \
    else \
        echo "Skipping Chromium: this image cannot detonate links."; \
    fi

RUN useradd --create-home --uid 10001 appuser
COPY --chown=appuser:appuser . .

# The SQLite database lives here. For local docker run, mount a volume:
#   docker run -p 8080:8080 -v reportit-data:/data --env-file .env reportit
# For Cloud Run, mount a Cloud Storage bucket instead (see README's Deploy
# section) so the database survives cold starts and redeploys.
ENV THREADLINE_DB=/data/threadline.db
RUN mkdir /data && chown appuser:appuser /data
VOLUME /data

USER appuser
EXPOSE 8080
# $PORT is honoured if the platform sets one (some PaaS hosts do); the shell
# form lets it expand at start time. On Hugging Face Spaces nothing is
# injected and routing comes from `app_port` in README.md's frontmatter,
# which must match the 8080 default below.
#
# Every host this runs on terminates TLS at a proxy and forwards plain HTTP
# with X-Forwarded-Proto: https. Without --proxy-headers, uvicorn ignores
# that and app.py's request.base_url comes back as http://, which breaks the
# Google OAuth redirect_uri (it'll never match a registered https:// URI).
# --forwarded-allow-ips='*' is acceptable because the container is never
# reachable except through that proxy.
CMD uvicorn app:app --host 0.0.0.0 --port ${PORT:-8080} \
    --proxy-headers --forwarded-allow-ips='*'
