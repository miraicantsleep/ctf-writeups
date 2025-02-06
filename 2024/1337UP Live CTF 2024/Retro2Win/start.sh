#!/bin/bash

# Stop script on any errors
set -e

# Stop and remove any existing containers and orphan containers
docker-compose down --remove-orphans

# Build the images
docker-compose build

# Start the containers
docker-compose up