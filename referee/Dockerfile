# referee/Dockerfile
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY referee/ referee/
COPY shared/ shared/

ENV PYTHONPATH=/app

CMD ["python", "-m", "referee.main"]
