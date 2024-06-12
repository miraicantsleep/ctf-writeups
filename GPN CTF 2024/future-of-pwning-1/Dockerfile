# docker build -t future-of-pwning-1 . && docker run -p 5000:5000 --rm -it future-of-pwning-1
FROM python:3.12

RUN apt-get update -y && apt-get install -y --no-install-recommends build-essential curl \
&& apt-get clean && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir flask

RUN curl -L https://github.com/ForwardCom/bintools/archive/779c06891cba05a97a214a23b7a63aeff25d983a.tar.gz | tar zxf -
WORKDIR bintools-779c06891cba05a97a214a23b7a63aeff25d983a
RUN make -f forw.make && mkdir /app && cp forw instruction_list.csv /app

WORKDIR /app

ARG FLAG=GPNCTF{fake_flag}
RUN echo "$FLAG" > /flag

COPY app.py ./
EXPOSE 5000
ENV FLASK_APP=app.py
CMD ["flask", "run", "--host=0.0.0.0"]
