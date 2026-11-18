# TrustTrain API image (CPU-only).
FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1

RUN groupadd --system trusttrain && useradd --system --gid trusttrain --home /app trusttrain

WORKDIR /app
COPY backend/requirements.txt ./requirements.txt
# Install the CPU build of PyTorch first so the large CUDA wheels are not pulled in.
RUN pip install --index-url https://download.pytorch.org/whl/cpu torch==2.15.0 \
    && pip install -r requirements.txt

COPY backend/app ./app
COPY backend/alembic ./alembic
COPY backend/alembic.ini ./alembic.ini

RUN mkdir -p /data && chown trusttrain:trusttrain /data
USER trusttrain

ENV TRUSTTRAIN_DATA_DIR=/data
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=4)"

# Apply migrations, then serve.
CMD ["sh", "-c", "alembic upgrade head && uvicorn app.main:app --host 0.0.0.0 --port 8000 --proxy-headers"]
