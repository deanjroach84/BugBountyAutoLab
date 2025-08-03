#!/bin/bash

# Usage: ./bugbounty-auto.sh example.com

if [ -z "$1" ]; then
    echo "Usage: $0 example.com"
    exit 1
fi

domain="$1"
timestamp=$(date +%Y%m%d_%H%M%S)
outdir="recon/${domain}_${timestamp}"
mkdir -p "$outdir"
cd "$outdir" || exit 1

echo "[*] Starting Recon on $domain..."
echo "[*] Output will be stored in: $outdir"

# 1. Subdomain Enumeration
echo "[+] Running Amass..."
amass enum -passive -d "$domain" -o amass.txt

echo "[+] Running Sublist3r..."
sublist3r -d "$domain" -o sublist3r.txt

echo "[+] Running Assetfinder..."
assetfinder --subs-only "$domain" > assetfinder.txt

# Merge & Deduplicate
cat amass.txt sublist3r.txt assetfinder.txt | sort -u > all_subs.txt

# 2. Alive Hosts
echo "[+] Checking Alive Hosts with httpx..."
httpx -silent -l all_subs.txt -o live_hosts.txt

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
echo "[+] Fuzzing common paths on live hosts with ffuf..."
while read -r url; do
    clean_url=$(echo "$url" | sed 's|https\?://||g' | tr '/' '_')
    ffuf -u "${url}/FUZZ" -w /usr/share/wordlists/dirb/common.txt -of json -o "ffuf_${clean_url}.json"
done < live_hosts.txt

# 7. Crawling + JS Endpoint Collection
echo "[+] Crawling targets with gospider..."
gospider -S live_hosts.txt -o spider_output > gospider.log

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
grep "?" urls.txt > params.txt
mkdir -p sqlmap_results
while read -r url; do
    clean=$(echo "$url" | sed 's|https\?://||g' | tr '/' '_')
    sqlmap -u "$url" --batch --level=2 --risk=2 --crawl=1 --random-agent \
        --timeout=10 --threads=3 --output-dir="sqlmap_results/${clean}"
done < params.txt

# 11. Nmap Full Port + Vuln Scan
echo "[+] Running full-port Nmap scan with vuln scripts..."
while read -r raw_host; do
    # If scheme missing, assume http
    if [[ "$raw_host" =~ ^https?:// ]]; then
        url="$raw_host"
    else
        url="http://$raw_host"
    fi

    # Extract clean IP/domain
    clean_host=$(echo "$url" | sed -E 's|^https?://||' | cut -d'/' -f1)

    if [[ -z "$clean_host" ]]; then
        echo "[!] Skipping invalid entry: $raw_host"
        continue
    fi

    echo "[*] Scanning $url ($clean_host) with Nmap vuln scripts..."
    sudo nmap -p- -sV -T4 -Pn --script vuln -oN "nmap_${clean_host}.txt" "$clean_host"
done < live_hosts.txt

# 12. Nikto + Gobuster
echo "[+] Running Nikto and Gobuster scans..."
while read -r raw_host; do
    if [[ "$raw_host" =~ ^https?:// ]]; then
        url="$raw_host"
    else
        url="http://$raw_host"
    fi

    clean_host=$(echo "$url" | sed -E 's|^https?://||' | tr '/' '_')

    echo "[*] Nikto scanning $url..."
    nikto -host "$url" -output "nikto_${clean_host}.txt"

    echo "[*] Gobuster scanning $url..."
    gobuster dir -u "$url" -w /usr/share/wordlists/dirb/common.txt -o "gobuster_${clean_host}.txt"
done < live_hosts.txt

echo "[✔] All recon and scans completed."
echo "[✔] Results saved in: $outdir"
