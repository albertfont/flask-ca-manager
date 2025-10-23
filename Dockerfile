FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    DATA_ROOT=/data

# System deps for cryptography
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt ./
RUN pip install -r requirements.txt

COPY . .

# Create data dirs (mounted as volumes at runtime)
RUN mkdir -p /data/db /data/certs

EXPOSE 8000

CMD ["gunicorn", "-w", "2", "-b", "0.0.0.0:5090", "wsgi:app"]