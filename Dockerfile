FROM python:3.12-slim

WORKDIR /app

# Tesseract enables OCR of image-based phishing (threadline/ocr.py).
RUN apt-get update \
    && apt-get install -y --no-install-recommends tesseract-ocr \
    && rm -rf /var/lib/apt/lists/*

# Layer-cache the dependencies separately from the app code.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

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
CMD uvicorn app:app --host 0.0.0.0 --port ${PORT:-8080}
