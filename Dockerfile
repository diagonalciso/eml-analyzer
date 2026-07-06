# eml-analyzer web UI — stdlib http.server front end for the CLI analyzer.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=8104

WORKDIR /app

# Install deps first for layer caching.
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8104

# Simple healthcheck against the built-in /health endpoint.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import os,urllib.request,sys; \
        urllib.request.urlopen('http://127.0.0.1:%s/health' % os.getenv('PORT','8104'), timeout=3); \
        sys.exit(0)" || exit 1

CMD ["python", "webapp.py"]
