FROM python:3.10

EXPOSE 80
EXPOSE 443
EXPOSE 8080
EXPOSE 8000

RUN mkdir static
RUN mkdir templates
ADD app.py .
ADD bak .
ADD db.py .
ADD db.sqlite .
ADD nmap.xsl .
ADD Pipfile .
ADD Procfile .
ADD requirements.txt .
ADD test.py .
ADD README.md .
COPY static /static/
COPY templates /templates/

RUN apt update && apt upgrade -y
RUN apt install nmap -y
RUN pip install -r requirements.txt

ENV OPENAI_API_KEY=''

CMD [ "sh", "-c","python ./app.py ${OPENAI_API_KEY}" ]
