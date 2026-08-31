FROM python:3.14-slim

WORKDIR /app

COPY mcp-server/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# The backend app package is mounted at runtime (shares the same code as the
# api container) so the MCP server can import it for in-process tool execution.
COPY mcp-server /app/mcp-server
COPY backend/app /app/app
COPY shared /app/shared

WORKDIR /app/mcp-server

EXPOSE 8082

CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8082"]
