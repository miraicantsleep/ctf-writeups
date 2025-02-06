FROM ubuntu:16.04

# Install necessary packages
RUN apt-get update -y && \
    apt-get install -y build-essential socat htop && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create a non-root user
RUN useradd -u 1000 -d /home/user -s /bin/bash user

# Set the working directory
WORKDIR /home/user

# Copy the binary and flag into the container
COPY retro2win /home/user/
COPY flag.txt /home/user/

# Set permissions to make necessary files read-only
RUN chmod 444 /home/user/flag.txt
RUN chmod 111 /home/user/retro2win
RUN chmod -R 555 /home/user

# Expose port 1338 to the outside world
EXPOSE 1338

# Switch to non-root user for additional security
USER user

# Start the service with socat
CMD ["socat", "TCP-LISTEN:1338,reuseaddr,fork", "EXEC:/home/user/retro2win,pty,echo=0"]
