FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY dashboard/ dashboard/
COPY shared/ shared/

ENV PYTHONPATH=/app
EXPOSE 8080

CMD ["python", "-m", "dashboard.app"]
