#!/bin/bash

# Usage: ./bugbounty-auto.sh example.com

domain=$1
outdir="recon/$domain"
mkdir -p $outdir

# 0. CHECK AND INSTALL GO FIRST
echo "[*] Checking for Go (golang)..."

if ! command -v go &> /dev/null; then
    echo "[!] Go is not installed. Installing Go..."
    sudo apt update
    sudo apt install -y golang
else
    echo "[+] Go is already installed."
fi

export PATH=$PATH:$HOME/go/bin
export PATH=$PATH:$(go env GOPATH)/bin

# 1. TOOL CHECK & AUTO-INSTALL
echo "[*] Checking required tools..."

tools=(
    amass
    sublist3r
    assetfinder
    httpx
    whatweb
    wafw00f
    nuclei
    ffuf
    gospider
    waybackurls
    gau
    dalfox
    sqlmap
    gowitness
)

install_tool() {
    tool=$1
    echo "[!] $tool not found. Installing..."

    case $tool in
        amass)
            sudo apt install -y amass
            ;;
        sublist3r)
            sudo apt install -y sublist3r
            ;;
        assetfinder)
            go install github.com/tomnomnom/assetfinder@latest
            ;;
        httpx)
            go install github.com/projectdiscovery/httpx/cmd/httpx@latest
            ;;
        whatweb)
            sudo apt install -y whatweb
            ;;
        wafw00f)
            sudo apt install -y wafw00f
            ;;
        nuclei)
            go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
            ;;
        ffuf)
            go install github.com/ffuf/ffuf@latest
            ;;
        gospider)
            go install github.com/jaeles-project/gospider@latest
            ;;
        waybackurls)
            go install github.com/tomnomnom/waybackurls@latest
            ;;
        gau)
            go install github.com/lc/gau/v2/cmd/gau@latest
            ;;
        dalfox)
            go install github.com/hahwul/dalfox/v2@latest
            ;;
        sqlmap)
            sudo apt install -y sqlmap
            ;;
        gowitness)
            go install github.com/sensepost/gowitness@latest
            ;;
        *)
            echo "[-] Unknown tool: $tool"
            ;;
    esac
}

for tool in "${tools[@]}"; do
    if ! command -v $tool &> /dev/null; then
        install_tool $tool
    else
        echo "[+] $tool is installed."
    fi
done

echo "[✔] All tools are ready."

# ----------------------------------------
# Begin Scanning Phase
# ----------------------------------------

echo "[*] Starting Recon on $domain..."
cd $outdir

# 1. Subdomain Enumeration
echo "[+] Running Amass..."
amass enum -passive -d $domain -o amass.txt

echo "[+] Running Sublist3r..."
sublist3r -d $domain -o sublist3r.txt

echo "[+] Running Assetfinder..."
assetfinder --subs-only $domain > assetfinder.txt

# Merge & Deduplicate
cat amass.txt sublist3r.txt assetfinder.txt | sort -u > all_subs.txt

# 2. Alive Hosts
echo "[+] Checking Alive Hosts with httpx..."
cat all_subs.txt | httpx -silent > live_hosts.txt

# 3. Web Tech Stack
echo "[+] Fingerprinting with WhatWeb..."
whatweb -i live_hosts.txt > whatweb.txt

# 4. WAF Detection
echo "[+] Checking for WAFs..."
wafw00f -i live_hosts.txt > wafs.txt

# 5. Nuclei Scan
echo "[+] Running nuclei with default templates..."
nuclei -l live_hosts.txt -t ~/nuclei-templates/ -o nuclei_results.txt

# 6. Dir Fuzzing with ffuf
echo "[+] Fuzzing common paths on live hosts..."
for url in $(cat live_hosts.txt); do
    ffuf -u $url/FUZZ -w /usr/share/wordlists/dirb/common.txt -o ffuf_$(echo $url | sed 's/https\?:\/\///g').json
done

# 7. Crawling + JS Endpoint Collection
echo "[+] Crawling targets with gospider..."
gospider -S live_hosts.txt -o spider_output

# 8. Pulling URLs from archive
echo "[+] Pulling URLs from Wayback + Gau..."
cat all_subs.txt | waybackurls > wayback.txt
cat all_subs.txt | gau > gau.txt
cat wayback.txt gau.txt | sort -u > urls.txt

# 9. XSS Scanner (Dalfox)
echo "[+] Scanning for XSS with dalfox..."
dalfox file urls.txt --output dalfox_results.txt

# 10. SQLi Scanner (sqlmap)
echo "[+] Scanning for SQLi with sqlmap..."
cat urls.txt | grep "?" > params.txt
while read url; do
    sqlmap -u "$url" --batch --level=2 --risk=2 --crawl=1 --random-agent --timeout=10 --threads=3 --output-dir=sqlmap_results
done < params.txt

# 11. Screenshot Alive Hosts (Optional)
echo "[+] Taking screenshots of live hosts..."
gowitness file -f live_hosts.txt -P screenshots/

echo "[✔] All tasks complete. Output saved in: $outdir"

