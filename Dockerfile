FROM python:3.11-slim

WORKDIR /app

# system deps needed for the cryptography package + reportlab (pdf_generator.py)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential libssl-dev libffi-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Runtime dirs that must exist even on a fresh container. Real keys/ and
# data/ are never copied into the image itself (see .dockerignore): they
# are either generated fresh on first boot (demo mode, core/startup.py)
# or mounted from a persistent volume (production mode). Baking them into
# the image means every rebuild silently resets or leaks them.
RUN mkdir -p data keys sealed samples

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

CMD ["uvicorn", "backend.api:app", "--host", "0.0.0.0", "--port", "8000"]
