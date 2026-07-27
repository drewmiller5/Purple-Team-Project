# blue_agent/Dockerfile
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY blue_agent/ blue_agent/
COPY shared/ shared/

ENV PYTHONPATH=/app

CMD ["python", "-m", "blue_agent.main"]
