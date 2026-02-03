FROM python:3.13-slim

RUN apt-get update -qq && \
    apt-get install -y -qq --no-install-recommends \
        curl dnsutils make && \
    rm -rf /var/lib/apt/lists/*

COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /usr/local/bin/

WORKDIR /app

# Install deps first for caching
COPY pyproject.toml ./
RUN uv sync --no-install-project

# Copy source
COPY . .
RUN uv sync

CMD ["bash"]
