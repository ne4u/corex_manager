FROM python:3.12-slim

WORKDIR /app

COPY mcp-gateway/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY shared /app/shared
COPY mcp-gateway /app/gateway

WORKDIR /app/gateway

RUN mkdir -p /app/data/mcp

EXPOSE 8081

ENV PYTHONPATH=/app

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8081"]
