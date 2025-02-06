FROM ubuntu:latest AS build

RUN apt-get update -y && apt-get install build-essential -y --no-install-recommends \
&& apt-get clean && rm -rf /var/lib/apt/lists/*

COPY song_rater.c .
RUN gcc -no-pie -fno-stack-protector -O0 song_rater.c -o song_rater

FROM ubuntu:latest

RUN apt-get update -y && apt-get install socat -y --no-install-recommends \
&& apt-get clean && rm -rf /var/lib/apt/lists/*

COPY --from=build song_rater song_rater
COPY run.sh run.sh

ARG FLAG=GPNCTF{fake_flag}
RUN echo "$FLAG" > /flag

EXPOSE 1337

ENTRYPOINT [ "socat", "-v", "tcp-l:1337,reuseaddr,fork", "EXEC:./run.sh,stderr" ]
