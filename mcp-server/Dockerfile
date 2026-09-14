FROM python:3.14-alpine

WORKDIR /app/mcp-server

# The MCP server is a thin proxy: tools are discovered from the backend's
# OpenAPI spec and forwarded to the api service over internal HTTPS, so only
# its own slim requirements are needed (no backend dependency tree).
COPY mcp-server/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt \
    && pip uninstall -y pip setuptools

COPY mcp-server /app/mcp-server

EXPOSE 8082

CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8082"]
