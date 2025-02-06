FROM ubuntu:16.04

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
COPY drone /home/user/
COPY drone_manual.txt /home/user/

# Set permissions to make necessary files read-only
RUN chmod 444 /home/user/drone_manual.txt
RUN chmod 111 /home/user/drone
RUN chmod -R 555 /home/user

# Expose port 1340
EXPOSE 1340

# Switch to non-root user for additional security
USER user

# Start the service with socat
CMD ["socat", "TCP-LISTEN:1340,reuseaddr,fork", "EXEC:/home/user/drone,pty,echo=0"]
