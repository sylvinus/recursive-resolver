FROM python:3.13-slim

RUN apt-get update -qq && \
    apt-get install -y -qq --no-install-recommends \
        curl dnsutils make && \
    rm -rf /var/lib/apt/lists/*

# Pinned, not :latest: a floating tag makes the image non-reproducible and
# pulls unreviewed uv releases into the build. Bump this deliberately.
COPY --from=ghcr.io/astral-sh/uv:0.12.3 /uv /uvx /usr/local/bin/

WORKDIR /app

# Install deps first for caching
COPY pyproject.toml ./
RUN uv sync --no-install-project --all-extras

# Copy source
COPY . .
RUN uv sync --all-extras

CMD ["bash"]
