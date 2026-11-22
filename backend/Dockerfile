FROM python:3.11-slim

WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=8000

# Install build dependencies for capstone and networking tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    iproute2 \
    net-tools \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY backend/pyproject.toml /app/
RUN pip install --no-cache-dir .

COPY backend /app/backend
COPY rules /app/rules
COPY sandbox/sample_artifacts /app/sandbox/sample_artifacts

EXPOSE 8000

CMD ["uvicorn", "backend.app.main:app", "--host", "0.0.0.0", "--port", "8000"]
