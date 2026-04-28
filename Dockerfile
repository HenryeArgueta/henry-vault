FROM python:3.12-slim

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir .

VOLUME ["/data"]
ENV HENRY_VAULT_DB=/data/vault.db
EXPOSE 8787

CMD ["hv", "--db", "/data/vault.db", "web", "--host", "127.0.0.1", "--port", "8787"]
