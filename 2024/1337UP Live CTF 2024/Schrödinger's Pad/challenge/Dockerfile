FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN useradd -m user
USER user

EXPOSE 1337

CMD ["python", "server.py"]
