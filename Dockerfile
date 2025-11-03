FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    sudo \
    wireguard \
    wireguard-tools \
    iproute2 \
    iptables \
    curl \
    wget \
    gnupg \
    ca-certificates \
    openresolv \
    # Chrome dependencies
    fonts-liberation \
    libasound2 \
    libatk-bridge2.0-0 \
    libatk1.0-0 \
    libatspi2.0-0 \
    libcups2 \
    libdbus-1-3 \
    libdrm2 \
    libgbm1 \
    libgtk-3-0 \
    libnspr4 \
    libnss3 \
    libwayland-client0 \
    libxcomposite1 \
    libxdamage1 \
    libxfixes3 \
    libxkbcommon0 \
    libxrandr2 \
    xdg-utils \
    # Firefox dependencies
    firefox-esr \
    && rm -rf /var/lib/apt/lists/*

# Install Google Chrome
RUN wget -q -O /tmp/google-chrome-key.pub https://dl-ssl.google.com/linux/linux_signing_key.pub \
    && mkdir -p /etc/apt/keyrings \
    && cat /tmp/google-chrome-key.pub | gpg --dearmor -o /etc/apt/keyrings/google-chrome.gpg \
    && echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/google-chrome.gpg] http://dl.google.com/linux/chrome/deb/ stable main" > /etc/apt/sources.list.d/google-chrome.list \
    && apt-get update \
    && apt-get install -y google-chrome-stable \
    && rm -rf /var/lib/apt/lists/* /tmp/google-chrome-key.pub

# Install ChromeDriver
RUN apt-get update && apt-get install -y unzip && \
    CHROME_VERSION=$(google-chrome --version | awk '{print $3}') && \
    CHROME_MAJOR=$(echo $CHROME_VERSION | cut -d'.' -f1) && \
    echo "Chrome version: $CHROME_VERSION (major: $CHROME_MAJOR)" && \
    CHROMEDRIVER_VERSION=$(curl -s "https://googlechromelabs.github.io/chrome-for-testing/LATEST_RELEASE_$CHROME_MAJOR") && \
    echo "ChromeDriver version: $CHROMEDRIVER_VERSION" && \
    wget -O /tmp/chromedriver-linux64.zip "https://storage.googleapis.com/chrome-for-testing-public/$CHROMEDRIVER_VERSION/linux64/chromedriver-linux64.zip" && \
    unzip /tmp/chromedriver-linux64.zip -d /tmp/ && \
    mv /tmp/chromedriver-linux64/chromedriver /usr/local/bin/chromedriver && \
    chmod +x /usr/local/bin/chromedriver && \
    rm -rf /tmp/chromedriver-linux64.zip /tmp/chromedriver-linux64 && \
    rm -rf /var/lib/apt/lists/*

# Install GeckoDriver for Firefox
RUN GECKODRIVER_VERSION=$(curl -s https://api.github.com/repos/mozilla/geckodriver/releases/latest | grep -oP '"tag_name": "\K(.*)(?=")') && \
    wget -O /tmp/geckodriver.tar.gz https://github.com/mozilla/geckodriver/releases/download/$GECKODRIVER_VERSION/geckodriver-$GECKODRIVER_VERSION-linux64.tar.gz && \
    tar -xzf /tmp/geckodriver.tar.gz -C /usr/local/bin/ && \
    chmod +x /usr/local/bin/geckodriver && \
    rm /tmp/geckodriver.tar.gz

# Set up working directory
WORKDIR /app

# Copy requirements file
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the scraper script
COPY scraper.py .

# Create necessary directories
RUN mkdir -p /app/workdir /app/workdir/_tmp /app/workdir/tsv_ /app/wireguard_configs

# Configure sudo for WireGuard (no password required)
RUN echo "ALL ALL=(ALL) NOPASSWD: /usr/bin/wg-quick" >> /etc/sudoers

# Set environment variable
ENV WORKDIR=/app/workdir

# Default command (can be overridden in docker-compose)
CMD ["/bin/bash"]
