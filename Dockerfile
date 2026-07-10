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

# The SQLite database lives here — mount a volume to persist it:
#   docker run -p 8000:8000 -v reportit-data:/data --env-file .env reportit
ENV THREADLINE_DB=/data/threadline.db
RUN mkdir /data
VOLUME /data

EXPOSE 8000
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
