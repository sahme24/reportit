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
# itself is a separate download, and without it every sandbox detonation fails
# at launch. --with-deps pulls the shared libraries headless Chromium needs on
# a slim image. This adds roughly 400 MB; drop both lines (and set
# REPORTIT_SANDBOX=off) if you'd rather ship a small image without link
# detonation.
RUN playwright install --with-deps chromium

COPY . .

# The SQLite database lives here. For local docker run, mount a volume:
#   docker run -p 8080:8080 -v reportit-data:/data --env-file .env reportit
# For Cloud Run, mount a Cloud Storage bucket instead (see README's Deploy
# section) so the database survives cold starts and redeploys.
ENV THREADLINE_DB=/data/threadline.db
RUN mkdir /data
VOLUME /data

EXPOSE 8080
# Cloud Run injects $PORT (defaults to 8080) and expects the container to
# listen on it; the shell form lets that env var expand at start time.
#
# Cloud Run's proxy terminates TLS and forwards to the container over plain
# HTTP, setting X-Forwarded-Proto: https. Without --proxy-headers, uvicorn
# ignores that and app.py's request.base_url comes back as http://, which
# breaks the Google OAuth redirect_uri (it'll never match a registered
# https:// URI). --forwarded-allow-ips='*' is safe here specifically because
# Cloud Run's ingress means only its own proxy can ever reach this container.
CMD uvicorn app:app --host 0.0.0.0 --port ${PORT:-8080} \
    --proxy-headers --forwarded-allow-ips='*'
