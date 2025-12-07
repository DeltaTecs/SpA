# Use the official Go image as the base image
# Version 1.21 or higher is required as per instructions
FROM golang:1.21-bullseye

# Install dependencies
# Instructions mention: make, libpng
# We also need Node.js and npm for building the webapp
RUN apt-get update && apt-get install -y \
    build-essential \
    libpng-dev \
    git \
    curl \
    gnupg \
    && curl -fsSL https://deb.nodesource.com/setup_18.x | bash - \
    && apt-get install -y nodejs \
    && npm install -g npm@9 \
    && rm -rf /var/lib/apt/lists/*

# Set the working directory
WORKDIR /go/src/github.com/mattermost/mattermost

# Build argument for Mattermost version
ARG MATTERMOST_VERSION=master

# Clone the Mattermost repository
RUN git clone https://github.com/mattermost/mattermost.git . && \
    if [ "$MATTERMOST_VERSION" != "master" ]; then git checkout "$MATTERMOST_VERSION"; fi

# Change directory to webapp
WORKDIR /go/src/github.com/mattermost/mattermost/webapp

# Install npm dependencies and build
RUN npm install
RUN make dist

# Create the /mattermost directory structure
RUN mkdir -p /mattermost/bin /mattermost/data /mattermost/logs /mattermost/plugins /mattermost/client/plugins

# Copy client assets
RUN cp -r channels/dist/* /mattermost/client/

# Change directory to server
WORKDIR /go/src/github.com/mattermost/mattermost/server

# Build the server
RUN make build

# Copy binary
RUN cp bin/mattermost /mattermost/bin/

# Copy assets
# We copy the directories directly to /mattermost/
RUN cp -r config /mattermost/ || echo "config not found"
RUN cp -r fonts /mattermost/ || echo "fonts not found"
RUN cp -r templates /mattermost/ || echo "templates not found"
RUN cp -r i18n /mattermost/ || echo "i18n not found"

# Set working directory to /mattermost
WORKDIR /mattermost

# Expose the port
EXPOSE 8065

# Run the Mattermost server
CMD ["./bin/mattermost"]
