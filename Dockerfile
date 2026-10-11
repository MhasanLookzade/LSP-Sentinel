FROM python:3.10-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code and default configuration
COPY sentinel/ ./sentinel/
COPY sentinel.yaml ./sentinel.yaml
COPY pyproject.toml .

# Install package locally
RUN pip install --no-cache-dir -e .

EXPOSE 8443

# Run Web Dashboard and SRE daemon
CMD ["uvicorn", "sentinel.web.app:app", "--host", "0.0.0.0", "--port", "8443"]
