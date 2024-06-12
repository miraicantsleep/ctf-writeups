# docker build -t archventure-time . && docker run -it archventure-time
FROM ubuntu:24.04

RUN apt update
RUN apt install -y qemu-user libc6-arm64-cross libc6-riscv64-cross libc6-ppc64-cross

COPY ./chal /app/

WORKDIR /app

CMD ["./chal"]
