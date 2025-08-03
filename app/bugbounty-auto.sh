#!/bin/bash

# Usage: ./bugbounty-auto.sh example.com

# -------------------- Tool Check & Auto-Install --------------------
required_tools=(
    amass sublist3r assetfinder httpx whatweb wafw00f nuclei
    ffuf gospider waybackurls gau dalfox sqlmap nmap nikto gobuster grc
)

check_and_install_tools() {
    echo "[*] Checking required tools..."
    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            echo "[!] $tool not found. Attempting to install..."

            case "$tool" in
                assetfinder|httpx|gau)
                    go install "github.com/projectdiscovery/${tool}/cmd/${tool}@latest"
                    ;;
                amass)
                    sudo apt install -y amass
                    ;;
                sublist3r)
                    sudo apt install -y sublist3r
                    ;;
                whatweb|wafw00f|nmap|nikto|sqlmap|gobuster)
                    sudo apt install -y "$tool"
                    ;;
                nuclei)
                    go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
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
                dalfox)
                    go install github.com/hahwul/dalfox/v2@latest
                    ;;
                grc)
                    sudo apt install -y grc
                    ;;
                *)
                    echo "[!] No install routine defined for $tool. Please install manually."
                    ;;
            esac
        else
            echo "[+] $tool is installed."
        fi
    done
}

check_and_install_tools

# -------------------- Input Check --------------------
if [ -z "$1" ]; then
    echo "Usage: $0 example.com"
    exit 1
fi

# -------------------- Setup --------------------
domain="$1"
timestamp=$(date +%Y%m%d_%H%M%S)
outdir="recon/${domain}_${timestamp}"
mkdir -p "$outdir"
cd "$outdir" || exit 1

echo "[*] Starting Recon on $domain..."
echo "[*] Output will be stored in: $outdir"

# -------------------- Subdomain Enumeration --------------------
echo "[+] Running Amass..."
amass enum -passive -d "$domain" -o amass.txt

echo "[+] Running Sublist3r..."
sublist3r -d "$domain" -o sublist3r.txt

echo "[+] Running Assetfinder..."
assetfinder --subs-only "$domain" > assetfinder.txt

cat amass.txt sublist3r.txt assetfinder.txt | sort -u > all_subs.txt

# -------------------- Live Hosts --------------------
echo "[+] Checking Alive Hosts with httpx..."
httpx -silent -l all_subs.txt -o live_hosts.txt

# -------------------- Web Stack --------------------
echo "[+] Fingerprinting with WhatWeb..."
whatweb -i live_hosts.txt > whatweb.txt

echo "[+] Checking for WAFs..."
wafw00f -i live_hosts.txt > wafs.txt

# -------------------- Vulnerability Scanning --------------------
echo "[+] Running nuclei with default templates..."
nuclei -l live_hosts.txt -t ~/nuclei-templates/ -o nuclei_results.txt

# -------------------- Dir Fuzzing --------------------
echo "[+] Fuzzing common paths on live hosts with ffuf..."
while read -r url; do
    clean_url=$(echo "$url" | sed 's|https\?://||g' | tr '/' '_')
    ffuf -u "${url}/FUZZ" -w /usr/share/wordlists/dirb/small.txt -of json -o "ffuf_${clean_url}.json"
done < live_hosts.txt

# -------------------- Crawling --------------------
echo "[+] Crawling targets with gospider..."
gospider -S live_hosts.txt -o spider_output > gospider.log

# -------------------- Archive URL Pulling --------------------
echo "[+] Pulling URLs from Wayback + Gau..."
cat all_subs.txt | waybackurls > wayback.txt
cat all_subs.txt | gau > gau.txt
cat wayback.txt gau.txt | sort -u > urls.txt

# -------------------- XSS Scan --------------------
echo "[+] Scanning for XSS with dalfox..."
dalfox file urls.txt --output dalfox_results.txt

# -------------------- SQLi Scan --------------------
echo "[+] Scanning for SQLi with sqlmap..."
grep "?" urls.txt > params.txt
mkdir -p sqlmap_results
while read -r url; do
    clean=$(echo "$url" | sed 's|https\?://||g' | tr '/' '_')
    sqlmap -u "$url" --batch --level=2 --risk=2 --crawl=1 --random-agent \
        --timeout=10 --threads=3 --output-dir="sqlmap_results/${clean}"
done < params.txt

# -------------------- Nmap Scan --------------------
echo "[+] Running full-port Nmap scan with vuln scripts..."
while read -r raw_host; do
    [[ "$raw_host" =~ ^https?:// ]] && url="$raw_host" || url="http://$raw_host"
    clean_host=$(echo "$url" | sed -E 's|^https?://||' | cut -d'/' -f1)
    [[ -z "$clean_host" ]] && echo "[!] Skipping invalid entry: $raw_host" && continue

    echo "[*] Scanning $url ($clean_host) with Nmap vuln scripts..."
    sudo nmap -p- -sV -T4 -Pn --script vuln -oN "nmap_${clean_host}.txt" "$clean_host"
done < live_hosts.txt

# -------------------- Nikto + Gobuster --------------------
echo "[+] Running Nikto and Gobuster scans..."
while read -r raw_host; do
    [[ "$raw_host" =~ ^https?:// ]] && url="$raw_host" || url="http://$raw_host"
    clean_host=$(echo "$url" | sed -E 's|^https?://||' | tr '/' '_')

    echo "[*] Nikto scanning $url..."
    nikto -host "$url" -output "nikto_${clean_host}.txt"

    echo "[*] Gobuster scanning $url..."
    gobuster dir -u "$url" -w /usr/share/wordlists/dirb/small.txt -o "gobuster_${clean_host}.txt"
done < live_hosts.txt

echo "[✔] All recon and scans completed."
echo "[✔] Results saved in: $outdir"
