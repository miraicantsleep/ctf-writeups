FROM ubuntu:23.04 AS app

# Install necessary packages
RUN apt-get update -y && \
    apt-get install -y build-essential socat htop && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create a non-root user
RUN useradd -u 1001 -d /home/user -s /bin/bash user

# Set the working directory
WORKDIR /home/user

# Copy the binary and flag into the container
COPY rigged_slot2 /home/user/
COPY flag.txt /home/user/

# Set permissions to make necessary files read-only
RUN chmod 444 /home/user/flag.txt
RUN chmod 111 /home/user/rigged_slot2
RUN chmod -R 555 /home/user

# Expose port 1337
EXPOSE 1337

# Switch to non-root user for additional security
USER user

# Start the service with socat
CMD ["socat", "TCP-LISTEN:1337,reuseaddr,fork", "EXEC:/home/user/rigged_slot2,pty,echo=0"]
