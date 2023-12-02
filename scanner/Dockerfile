FROM python:3.11-slim

WORKDIR /app
COPY . /app
RUN pip install --no-cache-dir Flask Flask-RESTful python-nmap
EXPOSE 5000
ENV FLASK_APP=app.py
ENV FLASK_RUN_HOST=0.0.0.0
USER root
RUN apt-get update && \
    apt-get install -y nmap && \
    rm -rf /var/lib/apt/lists/*

CMD ["flask", "run"]
