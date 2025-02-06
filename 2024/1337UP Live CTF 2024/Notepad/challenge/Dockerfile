FROM ubuntu:18.04

# Install necessary packages for building and running the application
RUN apt-get update -y && \
    apt-get install -y build-essential socat htop && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create a non-root user
RUN useradd -u 1001 -d /home/user -s /bin/bash user

# Set the working directory to the user's home directory
WORKDIR /home/user

# Copy the source binary into the container
COPY flag /home/user/
COPY notepad /home/user/

# Set permissions to make necessary files read-only
RUN chmod 444 /home/user/flag
RUN chmod 111 /home/user/notepad
RUN chmod -R 555 /home/user

# Expose port 1341 to the outside world
EXPOSE 1341

# Switch to non-root user for additional security
USER user

# Start the service and ensure the working directory is correct
CMD ["socat", "TCP-LISTEN:1341,reuseaddr,fork", "EXEC:/home/user/notepad,pty,echo=0"]