FROM python:3.10

EXPOSE 443

RUN mkdir static
RUN mkdir templates
ADD app.py .
ADD auth_keys.db .
ADD requirements.txt .
ADD README.md .
ADD wsgi.py .
ADD nmapapi.service .
COPY static /static/
COPY templates /templates/

RUN apt update && apt upgrade -y
RUN apt install nmap -y
RUN pip install -r requirements.txt

ENTRYPOINT [ "gunicorn", "-w", "4", "-b", "0.0.0.0:443", "--timeout", "2400", "--max-requests", "0", "wsgi:app" ]