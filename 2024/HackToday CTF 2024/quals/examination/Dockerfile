FROM ubuntu:23.10 as ubuntu

FROM pwn.red/jail

COPY --from=ubuntu / /srv

ENV JAIL_TIME=60

COPY flag.txt /srv/app/flag.txt
COPY examination /srv/app/run