ARG PYTHON_IMAGE=docker.1ms.run/library/python:3.12-slim
FROM ${PYTHON_IMAGE}

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

ARG PIP_INDEX_URL=https://pypi.tuna.tsinghua.edu.cn/simple
ARG PIP_TRUSTED_HOST=pypi.tuna.tsinghua.edu.cn

RUN python -m pip install --index-url "${PIP_INDEX_URL}" --trusted-host "${PIP_TRUSTED_HOST}" --upgrade pip setuptools wheel

COPY pyproject.toml README.md ./
COPY src ./src

RUN python -m pip install --no-build-isolation --index-url "${PIP_INDEX_URL}" --trusted-host "${PIP_TRUSTED_HOST}" -e .

RUN mkdir -p /app/data /app/logs

ENV REGPILOT_HOST=0.0.0.0 \
    REGPILOT_PORT=8766

EXPOSE 8766

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import json, os, urllib.request; port=os.getenv('REGPILOT_PORT','8766'); print(json.load(urllib.request.urlopen(f'http://127.0.0.1:{port}/api/health', timeout=3)))"

CMD ["sh", "-c", "python -m regpilot.api --host ${REGPILOT_HOST:-0.0.0.0} --port ${REGPILOT_PORT:-8766}"]
