FROM python:3.11-slim
WORKDIR /app
# Root-cause fix: docker.io's apt package only installs dockerd (the
# daemon), never the `docker` CLI binary -- confirmed live via
# `dpkg -L docker.io` (no /usr/bin/docker). The docker Python SDK talks to
# the mounted docker.sock directly, so no CLI/apt dependency is needed here
# at all.
RUN pip install --no-cache-dir flask docker
COPY round_helper/ round_helper/
CMD ["python", "-m", "round_helper.app"]
