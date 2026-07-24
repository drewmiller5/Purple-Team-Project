FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends iputils-ping \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY target/ target/
COPY shared/ shared/

ENV PYTHONPATH=/app
EXPOSE 5000

CMD ["python", "-m", "target.app"]
