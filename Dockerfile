FROM python:3.11-slim@sha256:61e01f72680f86a5279ad510818ab7b2ee9f049822589d4e34e33e044360356c

WORKDIR /app

COPY requirements.txt .

RUN python -m pip install --no-cache-dir --upgrade pip==26.3 \
    && python -m pip install --no-cache-dir --only-binary=:all: -r requirements.txt \
    && python -m pip uninstall -y setuptools wheel \
    && python -m pip check

COPY app/sample_app.py .

USER 10001:10001

CMD ["python", "sample_app.py"]
