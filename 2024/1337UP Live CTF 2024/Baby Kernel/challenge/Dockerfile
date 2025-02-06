FROM ubuntu:latest

# Set non-interactive mode for apt-get
ENV DEBIAN_FRONTEND=noninteractive

# Install required packages
RUN apt-get update && \
    apt-get install -y qemu-system-x86 socat && \
    rm -rf /var/lib/apt/lists/*

# Create the /home/user directory and copy files
RUN mkdir -p /home/user
COPY boot.sh /home/user/
COPY bzImage /home/user/
COPY initramfs.cpio.gz /home/user/

# Set ownership to root and make the files read-only
RUN chown -R root:root /home/user && \
    chmod 555 /home/user/boot.sh && \
    chmod 444 /home/user/bzImage && \
    chmod 444 /home/user/initramfs.cpio.gz

# Run the socat command to listen on the desired port and execute boot.sh
CMD socat \
      TCP-LISTEN:1343,reuseaddr,fork \
      EXEC:"/home/user/boot.sh"
