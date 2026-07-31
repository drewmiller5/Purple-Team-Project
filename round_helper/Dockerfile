FROM python:3.11-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends docker.io \
    && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir flask
COPY round_helper/ round_helper/
CMD ["python", "-m", "round_helper.app"]
