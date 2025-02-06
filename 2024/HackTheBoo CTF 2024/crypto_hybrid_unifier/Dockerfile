FROM python:3.10-slim-buster 

RUN apt update

RUN mkdir app
# Add application
WORKDIR /app/application

COPY challenge/application .

COPY flag.txt /flag.txt

RUN pip3 install -r requirements.txt

EXPOSE 1337

ENV PYTHONDONTWRITEBYTECODE=1

ENTRYPOINT ["python3", "/app/application/app.py"]
