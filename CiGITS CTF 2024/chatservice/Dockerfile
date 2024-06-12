FROM ubuntu:18.04
ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update && \
    apt-get -y install curl \
    build-essential libcunit1-dev libudev-dev socat

RUN useradd ctf
WORKDIR /home/ctf

ADD chat /home/ctf/chat
ADD services /home/ctf/services
ADD flag /home/ctf/flag
ADD libc.so.6 /home/ctf/libc.so.6
ADD ld-linux-x86-64.so.2 /home/ctf/ld-linux-x86-64.so.2
ADD libseccomp.so.2 /home/ctf/libseccomp.so.2

RUN chown -R root:root  /home/ctf
RUN chmod -R 555        /home/ctf

EXPOSE 1337
ENTRYPOINT ["socat", "TCP-LISTEN:1337,reuseaddr,fork,nodelay,su=ctf", "EXEC:'timeout 60 ./services'"]