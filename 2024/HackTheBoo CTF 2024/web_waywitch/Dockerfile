# Use the official Node.js image as a base
FROM node:alpine

# Install openssl and supervisor
RUN apk add --no-cache --update supervisor openssl

WORKDIR /app

COPY src/ .
COPY config/supervisord.conf /etc/supervisord.conf
COPY --chown=root entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Install dependencies
RUN npm install express request mysql2

# Expose port 1337
EXPOSE 1337

# Copy flag
COPY flag.txt /flag.txt

# Generate Certificates using openssl
RUN openssl req -nodes -new -x509 -keyout /tmp/server.key -out /tmp/server.cert \
  -subj "/C=US/ST=State/L=City/O=Organization/OU=Unit/CN=localhost"

# Command to run the application
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf"]
