FROM ubuntu:22.04

# Install necessary packages for building and running the application
RUN apt-get update -y && \
    apt-get install -y build-essential socat htop && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create a non-root user
RUN useradd -u 1000 -d /home/user -s /bin/bash user

# Set the working directory
WORKDIR /home/user

# Copy the binary and flag into the container
COPY floormat_sale /home/user/
COPY flag.txt /home/user/

# Set permissions to make necessary files read-only
RUN chmod 444 /home/user/flag.txt
RUN chmod 111 /home/user/floormat_sale
RUN chmod -R 555 /home/user

# Expose port
EXPOSE 1339

# Switch to non-root user for additional security
USER user

# Start the service and ensure the working directory is correct
CMD ["socat", "TCP-LISTEN:1339,reuseaddr,fork", "EXEC:/home/user/floormat_sale,pty,echo=0"]