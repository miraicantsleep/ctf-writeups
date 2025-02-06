# Use a Debian-based Node.js image
FROM node:22-slim

# Install necessary build tools, libraries, and Chromium dependencies
RUN apt-get update && apt-get install -y \
    supervisor \
    chromium \
    chromium-driver \
    redis \
    gcc \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Set the Puppeteer Chromium environment
ENV PUPPETEER_SKIP_CHROMIUM_DOWNLOAD=true \
    PUPPETEER_EXECUTABLE_PATH=/usr/bin/chromium

# Copy flag
COPY flag.txt /

# Switch working directory
WORKDIR /app

# Copy the challenge files
COPY challenge .

# Switch to backend directory
WORKDIR /app/backend

# Install backend dependencies
RUN yarn

# Switch to the frontend directory
WORKDIR /app/frontend

# Install frontend dependencies and build assets
RUN yarn
RUN yarn build

# Copy and set permissions for supervisord configuration
COPY config/supervisord.conf /etc/supervisord.conf

# Expose necessary ports (80 for the app)
EXPOSE 80

# Start supervisord
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf"]