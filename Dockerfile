# Use an official lightweight version of an Ubuntu runtime as a parent image
FROM ubuntu:20.04

# Set the working directory
WORKDIR /app

# Avoid prompts from apt
ENV DEBIAN_FRONTEND=noninteractive

# Install build tools and OpenSSL
RUN apt-get update && \
    apt-get install -y build-essential openssl libssl-dev

# Copy the source code into the container
COPY . /app

# Compile the C program
RUN gcc -Wall -o https_server https_server.c -lssl -lcrypto

# Open port 80 for the HTTPS server
EXPOSE 80

# Run the server when the container launches
CMD ["./https_server"]
