FROM ubuntu:latest

# Install build dependencies as per instructions
RUN apt-get update && apt-get install -y \
    ca-certificates \
    curl \
    gnupg \
    git \
    python3 \
    make \
    g++ \
    libx11-dev \
    libxtst-dev \
    libpng-dev \
    # Additional runtime dependencies for Electron
    libnss3 \
    libatk-bridge2.0-0 \
    libgtk-3-0 \
    libgbm-dev \
    libxss1 \
    libasound2t64 \
    # Fixes for DBus and xdg-open
    dbus \
    dbus-x11 \
    xdg-utils \
    libnotify4 \
    libsecret-1-0 \
    gosu \
    && rm -rf /var/lib/apt/lists/*

ENV NVM_DIR /root/.nvm
RUN curl -o /tmp/install.sh https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.5/install.sh \
    && bash /tmp/install.sh \
    && . $NVM_DIR/nvm.sh \
    && nvm install --lts
RUN apt-get update
RUN mkdir -p /etc/apt/keyrings
RUN curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg
RUN echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_16.x nodistro main" | tee /etc/apt/sources.list.d/nodesource.list
RUN apt-get update
RUN apt-get install -y nodejs npm


# Create a non-root user
RUN useradd -m -s /bin/bash mattermost

WORKDIR /app
RUN chown mattermost:mattermost /app

USER mattermost

# Clone the repository
RUN git clone --branch v6.0.1 https://github.com/mattermost/desktop.git .

# install and run
RUN npm i
ENV ELECTRON_DISABLE_SANDBOX=1
CMD ["npm", "run", "watch"]
