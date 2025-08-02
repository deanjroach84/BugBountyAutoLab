FROM kalilinux/kali-rolling

# Install core tools
RUN apt-get update && apt-get install -y \
    git python3 python3-pip golang curl wget bash \
    amass sublist3r wafw00f whatweb sqlmap ffuf nmap \
    chromium gowitness sqlite3 \
    && apt-get clean

# Install Go-based tools
ENV PATH="/root/go/bin:$PATH"
RUN go install github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest && \
    go install github.com/tomnomnom/assetfinder@latest && \
    go install github.com/tomnomnom/waybackurls@latest && \
    go install github.com/jaeles-project/gospider@latest && \
    go install github.com/hahwul/dalfox/v2@latest && \
    go install github.com/ffuf/ffuf@latest && \
    go install github.com/lc/gau/v2/cmd/gau@latest && \
    go install github.com/sensepost/gowitness@latest

# Set up working directory
WORKDIR /app

# Copy everything
COPY ./app /app

# Install Python backend dependencies
RUN pip3 install -r backend/requirements.txt

# Expose dashboard port
EXPOSE 5000

# Default command
CMD ["bash", "start.sh"]