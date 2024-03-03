FROM debian@sha256:98d3b4b0cee264301eb1354e0b549323af2d0633e1c43375d0b25c01826b6790

# CHANGE VERSION ACCORDING TO THE DOCKERFILE IN CTF
#https://wiki.ubuntu.com/Releases

ENV DEBIAN_FRONTEND noninteractive

RUN apt update --fix-missing
RUN apt install -y git gdb git wget patchelf file strace tmux python3
RUN apt install -y netcat-openbsd python3-pip ruby-full valgrind vim xclip elfutils
RUN apt install -y checksec

WORKDIR /opt
RUN git clone https://github.com/pwndbg/pwndbg
WORKDIR /opt/pwndbg
ENV LC_ALL=C.UTF-8
RUN ./setup.sh

WORKDIR /opt
RUN wget https://github.com/io12/pwninit/releases/download/3.3.0/pwninit
RUN chmod +x pwninit

RUN gem install one_gadget
RUN pip install pwntools
WORKDIR /chal
CMD bash