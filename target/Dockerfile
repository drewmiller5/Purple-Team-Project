FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    iputils-ping curl gnupg apt-transport-https lsb-release procps \
    && curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" > /etc/apt/sources.list.d/wazuh.list \
    && apt-get update && apt-get install -y --no-install-recommends wazuh-agent=4.9.2-1 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY target/ target/
COPY shared/ shared/
COPY wazuh/agent/ossec.conf /var/ossec/etc/ossec.conf
COPY target/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENV PYTHONPATH=/app
EXPOSE 5000

ENTRYPOINT ["/entrypoint.sh"]
