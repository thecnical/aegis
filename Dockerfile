FROM python:3.12-slim

LABEL maintainer="Chandan Pandey"
LABEL description="Aegis — Modular Offensive Security Platform"

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    netcat-openbsd \
    smbclient \
    hydra \
    sqlmap \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy project files
COPY requirements.txt pyproject.toml ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN pip install --no-cache-dir -e .

# Create data directories
RUN mkdir -p data/logs data/reports data/evidence data/exports data/screenshots

ENTRYPOINT ["aegis"]
CMD ["--help"]
