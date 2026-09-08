FROM python:3.14-slim

WORKDIR /app

# The MCP server imports the backend app package for in-process tool
# execution, so it needs the backend's full dependency set in addition to its
# own slim requirements.
COPY requirements.txt /tmp/requirements-backend.txt
COPY mcp-server/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt -r /tmp/requirements-backend.txt

# The backend app package is mounted at runtime (shares the same code as the
# api container) so the MCP server can import it for in-process tool execution.
COPY mcp-server /app/mcp-server
COPY backend/app /app/app
COPY shared /app/shared

WORKDIR /app/mcp-server

# /app must be importable for `from app...` (backend package) and `shared`.
ENV PYTHONPATH=/app

EXPOSE 8082

CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8082"]
