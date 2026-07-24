# red_agent/Dockerfile
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY red_agent/ red_agent/
COPY shared/ shared/

ENV PYTHONPATH=/app

CMD ["python", "-m", "red_agent.main"]
