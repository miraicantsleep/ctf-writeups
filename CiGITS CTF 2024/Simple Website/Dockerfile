FROM python:slim

RUN apt update && apt install -y ncat

RUN useradd -U -m -s /bin/sh ctf

WORKDIR /app

COPY src/requirements.txt .

RUN pip install -r requirements.txt

COPY src/ .

COPY flag.txt /

RUN chown -R ctf:ctf /app
RUN chmod 555 /app && chown root:root /flag.txt

USER ctf

ENV HOST='0.0.0.0'
ENV PORT='5000'

EXPOSE 5000

CMD python3 app.py