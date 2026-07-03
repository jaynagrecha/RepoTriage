FROM python:3.12-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    python3-dev \
    libyara-dev \
    libfuzzy2 \
    libfuzzy-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt requirements-docker.txt ./
RUN pip install --no-cache-dir -r requirements-docker.txt

COPY . .
RUN chmod +x scripts/docker-entrypoint.sh

ENV PYTHONUNBUFFERED=1
ENV PLATFORM_DATA_DIR=/var/data
ENV WORKER_ENABLED=true

EXPOSE 10000
ENTRYPOINT ["scripts/docker-entrypoint.sh"]
