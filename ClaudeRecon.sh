#!/bin/bash

# CTF Recon Wrapper - Comprehensive reconnaissance automation
# Usage: ./recon.sh <target> [options]

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
THREADS=50
TIMEOUT=10
OUTPUT_DIR=""
TARGET=""
WORDLIST_DIR="/usr/share/wordlists"
TOOLS_CHECK=true
SUBDOMAIN_ONLY=false
PORT_ONLY=false
WEB_ONLY=false
VULN_ONLY=false
RECURSIVE_FFUF=false
FAST_MODE=false

# Tool paths (modify as needed)
GOBUSTER="gobuster"
FFUF="ffuf"
NMAP="nmap"
NIKTO="nikto"
WHATWEB="whatweb"
NUCLEI="nuclei"
SUBLIST3R="sublist3r"
AMASS="amass"

# Banner
print_banner() {
    echo -e "${PURPLE}"
    echo "  ▄████▄▄▄▄▄▄▄████  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗"
    echo "  ████████████████  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║" 
    echo "  ████████████████  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║"
    echo "  ████████████████  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║"
    echo "  ▀████▀▀▀▀▀▀▀████  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║"
    echo "                    ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝"
    echo -e "${NC}"
    echo -e "${CYAN}CTF Recon Automation Wrapper${NC}"
    echo -e "${YELLOW}Target: $TARGET${NC}"
    echo ""
}

usage() {
    cat << 'EOF'
Usage: ./recon.sh <target> [options]

Options:
  -o, --output DIR     Output directory (default: target_recon)
  -t, --threads NUM    Number of threads (default: 50)
  -w, --wordlist DIR   Wordlist directory (default: /usr/share/wordlists)
  --no-check          Skip tool availability check
  --subdomain-only    Only run subdomain enumeration
  --port-only         Only run port scanning
  --web-only          Only run web reconnaissance
  --vuln-only         Only run vulnerability scanning
  -ffuf, --recursive-ffuf  Enable recursive directory enumeration with FFUF
  --fast              Fast mode - skip redundant scans (no Nikto if Nuclei runs)
  -h, --help          Show this help message

Examples:
  ./recon.sh example.com
  ./recon.sh 10.10.10.100 -o /tmp/recon -t 100
  ./recon.sh target.htb --web-only -ffuf
  ./recon.sh target.com --fast
EOF
}

# Logging function
log() {
    local level=$1
    local message=$2
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    case $level in
        "INFO")
            echo -e "[${BLUE}INFO${NC}] ${timestamp} - $message"
            ;;
        "SUCCESS")
            echo -e "[${GREEN}SUCCESS${NC}] ${timestamp} - $message"
            ;;
        "WARNING")
            echo -e "[${YELLOW}WARNING${NC}] ${timestamp} - $message"
            ;;
        "ERROR")
            echo -e "[${RED}ERROR${NC}] ${timestamp} - $message"
            ;;
    esac
    
    if [ -n "$OUTPUT_DIR" ] && [ -d "$OUTPUT_DIR" ]; then
        echo "[$level] $timestamp - $message" >> "$OUTPUT_DIR/recon.log"
    fi
}

# Progress bar function
show_progress() {
    local current=$1
    local total=$2
    local prefix=$3
    local bar_length=50
    
    # Validate inputs are integers
    if ! [[ "$current" =~ ^[0-9]+$ ]] || ! [[ "$total" =~ ^[0-9]+$ ]]; then
        return
    fi
    
    # Avoid division by zero
    if [ "$total" -eq 0 ]; then
        total=1
    fi
    
    local progress=$((current * 100 / total))
    local filled_length=$((progress * bar_length / 100))
    
    # Create the bar
    local bar=""
    for ((i=0; i<filled_length; i++)); do
        bar="${bar}█"
    done
    for ((i=filled_length; i<bar_length; i++)); do
        bar="${bar}░"
    done
    
    # Print the progress bar
    printf "\r  ${CYAN}[*]${NC} %-30s [%s] %3d%% (%d/%d)" "$prefix" "$bar" "$progress" "$current" "$total"
    
    if [ "$current" -eq "$total" ]; then
        echo ""
    fi
}

# Monitor progress of a process
monitor_progress() {
    local process_name=$1
    local total_estimate=$2
    local check_command=$3
    local prefix=$4
    
    local count=0
    while pgrep -f "$process_name" > /dev/null; do
        # Try to get actual progress if possible
        if [ -n "$check_command" ]; then
            count=$(eval "$check_command" 2>/dev/null || echo "0")
            # Ensure count is a valid integer
            if ! [[ "$count" =~ ^[0-9]+$ ]]; then
                count=0
            fi
        else
            # Estimate progress based on time
            count=$((count + 1))
            if [ $count -gt $total_estimate ]; then
                count=$total_estimate
            fi
        fi
        
        show_progress "$count" "$total_estimate" "$prefix"
        sleep 1
    done
    
    # Ensure we show 100% completion
    show_progress "$total_estimate" "$total_estimate" "$prefix"
}

# Cool section headers like linpeas
print_section() {
    local title=$1
    local color=$2
    echo ""
    echo -e "${color}╔══════════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${color}║$(printf "%-78s" " $title")║${NC}"
    echo -e "${color}╚══════════════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

# Print findings in real-time
print_finding() {
    local type=$1
    local finding=$2
    local description=$3
    
    case $type in
        "PORT")
            echo -e "  ${GREEN}[+]${NC} ${CYAN}Port:${NC} $finding ${YELLOW}$description${NC}"
            ;;
        "SERVICE")
            echo -e "  ${GREEN}[+]${NC} ${PURPLE}Service:${NC} $finding ${YELLOW}$description${NC}"
            ;;
        "WEB")
            echo -e "  ${GREEN}[+]${NC} ${BLUE}Web:${NC} $finding ${YELLOW}$description${NC}"
            ;;
        "DIR")
            echo -e "  ${GREEN}[+]${NC} ${CYAN}Directory:${NC} $finding ${YELLOW}$description${NC}"
            ;;
        "VULN")
            echo -e "  ${RED}[!]${NC} ${RED}Vulnerability:${NC} $finding ${YELLOW}$description${NC}"
            ;;
        "SUBDOMAIN")
            echo -e "  ${GREEN}[+]${NC} ${PURPLE}Subdomain:${NC} $finding"
            ;;
        "INTERESTING")
            echo -e "  ${YELLOW}[*]${NC} ${YELLOW}Interesting:${NC} $finding ${YELLOW}$description${NC}"
            ;;
    esac
}

# Live monitoring function for port scan results
monitor_ports() {
    local scan_file=$1
    local temp_file="/tmp/ports_seen_$$"
    touch "$temp_file"
    
    while [ ! -f "$scan_file" ] || pgrep -f "nmap.*$TARGET" > /dev/null; do
        if [ -f "$scan_file" ]; then
            # Extract new open ports
            grep "open" "$scan_file" | while read -r line; do
                local port_info=$(echo "$line" | grep -oE "[0-9]+/[tcp|udp]+.*")
                if [ -n "$port_info" ] && ! grep -Fxq "$port_info" "$temp_file" 2>/dev/null; then
                    echo "$port_info" >> "$temp_file"
                    local port=$(echo "$port_info" | cut -d'/' -f1)
                    local service=$(echo "$line" | awk '{print $3}' | cut -d'?' -f1)
                    local version=$(echo "$line" | cut -d' ' -f4-)
                    print_finding "PORT" "$port/tcp" "($service) $version"
                fi
            done
        fi
        sleep 2
    done
    rm -f "$temp_file" 2>/dev/null
}

# Live monitoring for web directories
monitor_web_dirs() {
    local temp_file="/tmp/dirs_seen_$$"
    touch "$temp_file"
    
    while pgrep -f "gobuster.*$TARGET" > /dev/null || pgrep -f "ffuf.*$TARGET" > /dev/null; do
        for file in "$OUTPUT_DIR/web/gobuster_"*.txt; do
            if [ -f "$file" ]; then
                grep -E "Status: (200|301|302|403)" "$file" 2>/dev/null | while read -r line; do
                    if ! grep -Fxq "$line" "$temp_file" 2>/dev/null; then
                        echo "$line" >> "$temp_file"
                        local path=$(echo "$line" | awk '{print $1}')
                        local status=$(echo "$line" | grep -oE "Status: [0-9]+" | cut -d' ' -f2)
                        local size=$(echo "$line" | grep -oE "Size: [0-9]+" | cut -d' ' -f2)
                        print_finding "DIR" "$path" "(Status: $status, Size: $size)"
                    fi
                done
            fi
        done
        sleep 3
    done
    rm -f "$temp_file" 2>/dev/null
}

# Live monitoring for vulnerabilities
monitor_vulns() {
    local nuclei_file="$OUTPUT_DIR/vulns/nuclei.txt"
    local temp_file="/tmp/vulns_seen_$$"
    touch "$temp_file"
    
    while pgrep -f "nuclei.*$TARGET" > /dev/null; do
        if [ -f "$nuclei_file" ]; then
            while read -r line; do
                if [ -n "$line" ] && ! grep -Fxq "$line" "$temp_file" 2>/dev/null; then
                    echo "$line" >> "$temp_file"
                    print_finding "VULN" "$line" ""
                fi
            done < "$nuclei_file"
        fi
        sleep 2
    done
    rm -f "$temp_file" 2>/dev/null
}

# Check if tools are installed
check_tools() {
    if [ "$TOOLS_CHECK" = false ]; then
        return 0
    fi
    
    log "INFO" "Checking tool availability..."
    local missing_tools=()
    
    local tools=("$NMAP" "$GOBUSTER" "$FFUF" "$NIKTO" "$WHATWEB" "$NUCLEI")
    
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing_tools+=("$tool")
        fi
    done
    
    if [ ${#missing_tools[@]} -gt 0 ]; then
        log "WARNING" "Missing tools: ${missing_tools[*]}"
        log "WARNING" "Some scans may be skipped"
    else
        log "SUCCESS" "All essential tools found"
    fi
}

# Create directory structure
setup_directories() {
    log "INFO" "Setting up directory structure..."
    
    mkdir -p "$OUTPUT_DIR"/{nmap,web,subdomains,vulns,screenshots}
    
    if [ $? -eq 0 ]; then
        log "SUCCESS" "Directory structure created"
    else
        log "ERROR" "Failed to create directories"
        exit 1
    fi
}

# Subdomain enumeration
subdomain_enum() {
    print_section "SUBDOMAIN ENUMERATION" "$PURPLE"
    
    local tools_count=0
    local completed=0
    
    # Count available tools
    command -v "$SUBLIST3R" &> /dev/null && ((tools_count++))
    command -v "$AMASS" &> /dev/null && ((tools_count++))
    command -v "$GOBUSTER" &> /dev/null && [ -f "$WORDLIST_DIR/subdomains-top1million-5000.txt" ] && ((tools_count++))
    
    if [ $tools_count -eq 0 ]; then
        echo -e "  ${YELLOW}[*] No subdomain enumeration tools found${NC}"
        return 1
    fi
    
    # Sublist3r
    if command -v "$SUBLIST3R" &> /dev/null; then
        echo -e "  ${BLUE}[*]${NC} Running Sublist3r..."
        $SUBLIST3R -d "$TARGET" -o "$OUTPUT_DIR/subdomains/sublist3r.txt" &> /dev/null &
        local sublist3r_pid=$!
        monitor_progress "sublist3r.*$TARGET" 100 "" "Sublist3r progress" &
        wait $sublist3r_pid 2>/dev/null
        ((completed++))
        show_progress $completed $tools_count "Overall subdomain scan"
    fi
    
    # Amass
    if command -v "$AMASS" &> /dev/null; then
        echo -e "  ${BLUE}[*]${NC} Running Amass..."
        $AMASS enum -d "$TARGET" -o "$OUTPUT_DIR/subdomains/amass.txt" &> /dev/null &
        local amass_pid=$!
        monitor_progress "amass.*$TARGET" 100 "" "Amass progress" &
        wait $amass_pid 2>/dev/null
        ((completed++))
        show_progress $completed $tools_count "Overall subdomain scan"
    fi
    
    # Gobuster DNS
    if command -v "$GOBUSTER" &> /dev/null && [ -f "$WORDLIST_DIR/subdomains-top1million-5000.txt" ]; then
        echo -e "  ${BLUE}[*]${NC} Running Gobuster DNS..."
        $GOBUSTER dns -d "$TARGET" -w "$WORDLIST_DIR/subdomains-top1million-5000.txt" -o "$OUTPUT_DIR/subdomains/gobuster_dns.txt" -t "$THREADS" &> /dev/null &
        local gobuster_pid=$!
        local wl_size=$(wc -l < "$WORDLIST_DIR/subdomains-top1million-5000.txt")
        monitor_progress "gobuster.*dns.*$TARGET" "$wl_size" "grep -c '^' '$OUTPUT_DIR/subdomains/gobuster_dns.txt' 2>/dev/null || echo 0" "Gobuster DNS progress" &
        wait $gobuster_pid 2>/dev/null
        ((completed++))
        show_progress $completed $tools_count "Overall subdomain scan"
    fi
    
    # Display results in real-time
    if ls "$OUTPUT_DIR/subdomains/"*.txt 1> /dev/null 2>&1; then
        cat "$OUTPUT_DIR/subdomains/"*.txt | grep -E "^[a-zA-Z0-9.-]+\.$TARGET$|^[a-zA-Z0-9.-]+$" | sort -u > "$OUTPUT_DIR/subdomains/all_subdomains.txt"
        local count=$(wc -l < "$OUTPUT_DIR/subdomains/all_subdomains.txt")
        
        echo ""
        echo -e "  ${GREEN}[+] Found $count unique subdomains:${NC}"
        if [ "$count" -gt 0 ]; then
            head -20 "$OUTPUT_DIR/subdomains/all_subdomains.txt" | while read -r subdomain; do
                print_finding "SUBDOMAIN" "$subdomain"
            done
            if [ "$count" -gt 20 ]; then
                echo -e "  ${YELLOW}[*] ... and $(($count - 20)) more (check $OUTPUT_DIR/subdomains/all_subdomains.txt)${NC}"
            fi
        fi
    else
        echo -e "  ${YELLOW}[*] No subdomains found${NC}"
    fi
}

# Port scanning
port_scan() {
    print_section "PORT SCANNING" "$CYAN"
    
    if ! command -v "$NMAP" &> /dev/null; then
        echo -e "  ${RED}[!]${NC} Nmap not found, skipping port scan"
        return 1
    fi
    
    # Quick scan of top ports first for immediate feedback
    echo -e "  ${BLUE}[*]${NC} Running quick port scan..."
    $NMAP -T4 -F "$TARGET" -oN "$OUTPUT_DIR/nmap/quick_scan.txt" -oX "$OUTPUT_DIR/nmap/quick_scan.xml" > /dev/null 2>&1
    
    # Show quick results immediately
    echo ""
    if [ -f "$OUTPUT_DIR/nmap/quick_scan.txt" ]; then
        grep "open" "$OUTPUT_DIR/nmap/quick_scan.txt" | while read -r line; do
            local port=$(echo "$line" | grep -oE "[0-9]+/tcp" | cut -d'/' -f1)
            local service=$(echo "$line" | awk '{for(i=3;i<=NF;i++) printf "%s ", $i; print ""}' | sed 's/[[:space:]]*$//')
            print_finding "PORT" "$port/tcp" "$service"
        done
    fi
    
    # Start longer scans in background with live monitoring
    echo ""
    echo -e "  ${BLUE}[*]${NC} Starting comprehensive scans (running in background)..."
    echo -e "  ${YELLOW}[*]${NC} New findings will appear below as they're discovered..."
    echo ""
    
    # Full TCP scan
    echo -e "  ${BLUE}[*]${NC} Starting full TCP port scan (65535 ports)..."
    $NMAP -T4 -p- --min-rate=1000 "$TARGET" -oN "$OUTPUT_DIR/nmap/full_tcp.txt" -oX "$OUTPUT_DIR/nmap/full_tcp.xml" &> /dev/null &
    local full_tcp_pid=$!
    
    # Monitor full TCP scan progress - using simpler progress estimation
    monitor_progress "nmap.*-p-.*$TARGET" 100 "" "Full TCP scan" &
    local progress_pid=$!
    
    # UDP scan (top ports)
    $NMAP -sU -T4 --top-ports 100 "$TARGET" -oN "$OUTPUT_DIR/nmap/udp_scan.txt" -oX "$OUTPUT_DIR/nmap/udp_scan.xml" &> /dev/null &
    
    # Monitor for new ports in real-time
    monitor_ports "$OUTPUT_DIR/nmap/full_tcp.txt" &
    local monitor_pid=$!
    
    # Wait for full port scan to complete
    wait $full_tcp_pid
    kill $monitor_pid 2>/dev/null
    kill $progress_pid 2>/dev/null
    
    # Extract all open ports for service scanning
    echo ""
    echo -e "  ${BLUE}[*]${NC} Identifying services on discovered ports..."
    
    local open_ports=$(grep "open" "$OUTPUT_DIR/nmap/full_tcp.txt" 2>/dev/null | grep -oE "[0-9]+/tcp" | cut -d'/' -f1 | tr '\n' ',' | sed 's/,$//')
    
    if [ -n "$open_ports" ]; then
        # Service detection on ALL discovered open ports
        echo -e "  ${CYAN}[*]${NC} Running service detection on ports: $open_ports"
        $NMAP -sC -sV -T4 -p "$open_ports" "$TARGET" -oN "$OUTPUT_DIR/nmap/service_scan.txt" -oX "$OUTPUT_DIR/nmap/service_scan.xml" &> /dev/null
        
        # Show service scan results
        if [ -f "$OUTPUT_DIR/nmap/service_scan.txt" ]; then
            echo ""
            echo -e "  ${GREEN}[+] Service detection results:${NC}"
            grep "open" "$OUTPUT_DIR/nmap/service_scan.txt" | while read -r line; do
                local port=$(echo "$line" | grep -oE "[0-9]+/tcp" | cut -d'/' -f1)
                local service=$(echo "$line" | awk '{for(i=3;i<=NF;i++) printf "%s ", $i; print ""}' | sed 's/[[:space:]]*$//')
                print_finding "SERVICE" "$port/tcp" "$service"
            done
        fi
        
        # Also run vulnerability scripts on interesting ports
        local vuln_ports=$(echo "$open_ports" | tr ',' '\n' | grep -E "^(21|22|23|25|53|80|110|111|135|139|143|443|445|993|995|1723|3306|3389|5900|8080)$" | tr '\n' ',' | sed 's/,$//')
        if [ -n "$vuln_ports" ] && [ "$FAST_MODE" != true ]; then
            echo ""
            echo -e "  ${BLUE}[*]${NC} Running vulnerability scripts on high-value ports..."
            $NMAP --script vuln -T4 -p "$vuln_ports" "$TARGET" -oN "$OUTPUT_DIR/nmap/vuln_scan.txt" &> /dev/null
        fi
    fi
    
    # Wait for all remaining scans
    wait
    
    # Final summary
    echo ""
    local total_ports=$(grep -c "open" "$OUTPUT_DIR/nmap/full_tcp.txt" 2>/dev/null)
    echo -e "  ${GREEN}[+] Port scanning completed - Total open ports: ${total_ports:-0}${NC}"
}

# Recursive FFUF enumeration on discovered directories
recursive_ffuf_enum() {
    local base_url=$1
    local parent_dir=$2
    local depth=$3
    local max_depth=2
    
    if [ $depth -gt $max_depth ]; then
        return
    fi
    
    # Find a small wordlist for recursive scanning
    local small_wordlist=""
    local wordlists=(
        "$WORDLIST_DIR/dirb/small.txt"
        "$WORDLIST_DIR/dirbuster/directory-list-2.3-small.txt"
        "$WORDLIST_DIR/SecLists/Discovery/Web-Content/common.txt"
        "$WORDLIST_DIR/dirb/common.txt"
    )
    
    for wl in "${wordlists[@]}"; do
        if [ -f "$wl" ] && [ $(wc -l < "$wl") -lt 5000 ]; then
            small_wordlist="$wl"
            break
        fi
    done
    
    if [ -z "$small_wordlist" ]; then
        return
    fi
    
    local url="${base_url}${parent_dir}"
    local safe_filename=$(echo "$parent_dir" | tr '/' '_' | sed 's/^_//' | sed 's/_$//')
    local output_file="$OUTPUT_DIR/web/ffuf_recursive_${safe_filename}.json"
    
    echo -e "    ${CYAN}→${NC} Fuzzing: $url"
    
    # Run FFUF with proper error handling
    $FFUF -w "$small_wordlist" -u "${url}FUZZ" -mc 200,301,302,403 -t 30 -o "$output_file" -s &> /dev/null
    
    # Parse results and recursively scan found directories
    if [ -f "$output_file" ] && [ -s "$output_file" ]; then
        local dirs=$(cat "$output_file" | jq -r '.results[]? | select(.status == 301 or .status == 302) | .input.FUZZ' 2>/dev/null || true)
        
        if [ -n "$dirs" ]; then
            while IFS= read -r dir; do
                if [ -n "$dir" ]; then
                    print_finding "DIR" "${parent_dir}${dir}/" "(Recursive)"
                    # Recursive call for subdirectories
                    recursive_ffuf_enum "$base_url" "${parent_dir}${dir}/" $((depth + 1))
                fi
            done <<< "$dirs"
        fi
    fi
}

# Web reconnaissance
web_recon() {
    print_section "WEB RECONNAISSANCE" "$BLUE"
    
    local ports=("80" "443" "8080" "8443" "8000" "3000" "5000")
    local active_ports=()
    
    echo -e "  ${BLUE}[*]${NC} Checking for web services..."
    
    # Check which web ports are open
    for port in "${ports[@]}"; do
        if nc -zv "$TARGET" "$port" &> /dev/null; then
            active_ports+=("$port")
            print_finding "WEB" "Port $port" "Web service detected"
        fi
    done
    
    if [ ${#active_ports[@]} -eq 0 ]; then
        echo -e "  ${YELLOW}[*] No common web ports found open${NC}"
        return 1
    fi
    
    # Export active_ports for recursive FFUF
    ACTIVE_WEB_PORTS=("${active_ports[@]}")
    
    echo ""
    echo -e "  ${GREEN}[+] Found ${#active_ports[@]} web services${NC}"
    echo -e "  ${YELLOW}[*] Starting directory bruteforcing...${NC}"
    echo ""
    
    for port in "${active_ports[@]}"; do
        local protocol="http"
        if [ "$port" = "443" ] || [ "$port" = "8443" ]; then
            protocol="https"
        fi
        
        local url="${protocol}://${TARGET}:${port}"
        
        # WhatWeb for quick tech detection
        if command -v "$WHATWEB" &> /dev/null; then
            echo -e "  ${BLUE}[*]${NC} Analyzing $url..."
            local whatweb_output=$($WHATWEB "$url" -v 2>/dev/null | head -5)
            if [ -n "$whatweb_output" ]; then
                echo "$whatweb_output" > "$OUTPUT_DIR/web/whatweb_${port}.txt"
                local tech=$(echo "$whatweb_output" | grep -oE '[A-Za-z0-9.-]+\[[0-9.]+\]' | head -3 | tr '\n' ', ' | sed 's/,$//')
                if [ -n "$tech" ]; then
                    print_finding "INTERESTING" "$url" "Technologies: $tech"
                fi
            fi
        fi
        
        # Directory bruteforcing with live monitoring
        if command -v "$GOBUSTER" &> /dev/null; then
            local wordlists=(
                "$WORDLIST_DIR/dirb/common.txt"
                "$WORDLIST_DIR/dirbuster/directory-list-2.3-small.txt"
                "$WORDLIST_DIR/SecLists/Discovery/Web-Content/common.txt"
                "$WORDLIST_DIR/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt"
            )
            
            local found_wordlist=false
            for wl in "${wordlists[@]}"; do
                if [ -f "$wl" ]; then
                    found_wordlist=true
                    local wl_name=$(basename "$wl")
                    local wl_size=$(wc -l < "$wl" 2>/dev/null || echo "1000")
                    echo -e "  ${CYAN}[*]${NC} Bruteforcing directories with $wl_name ($wl_size entries)..."
                    
                    # Create a temporary error log
                    local error_log="/tmp/gobuster_error_$"
                    
                    # Run gobuster without the -q flag so we can see if it's actually running
                    $GOBUSTER dir -u "$url" -w "$wl" -x txt,html,php,asp,aspx,jsp -t "$THREADS" -o "$OUTPUT_DIR/web/gobuster_${port}_${wl_name}" --timeout "${TIMEOUT}s" --no-progress 2>"$error_log" &
                    local gobuster_pid=$!
                    
                    # Give gobuster a moment to start
                    sleep 2
                    
                    # Check if gobuster is actually running
                    if kill -0 $gobuster_pid 2>/dev/null; then
                        # Show progress for this wordlist
                        monitor_progress "gobuster.*dir.*$port" "$wl_size" "grep -c '^' '$OUTPUT_DIR/web/gobuster_${port}_${wl_name}' 2>/dev/null || echo 0" "Directory scan on port $port" &
                        local progress_pid=$!
                        
                        wait $gobuster_pid 2>/dev/null
                        local gobuster_exit=$?
                        kill $progress_pid 2>/dev/null
                        
                        # Check if gobuster failed
                        if [ $gobuster_exit -ne 0 ] && [ -f "$error_log" ]; then
                            echo -e "  ${YELLOW}[!]${NC} Gobuster encountered an issue:"
                            head -3 "$error_log" | sed 's/^/      /'
                        fi
                    else
                        echo -e "  ${RED}[!]${NC} Gobuster failed to start for port $port"
                        if [ -f "$error_log" ] && [ -s "$error_log" ]; then
                            head -3 "$error_log" | sed 's/^/      /'
                        fi
                    fi
                    
                    rm -f "$error_log" 2>/dev/null
                    break
                fi
            done
            
            if [ "$found_wordlist" = false ]; then
                echo -e "  ${YELLOW}[!]${NC} No suitable wordlists found for directory bruteforcing"
            fi
        fi
        
        # FFUF for parameter fuzzing
        if command -v "$FFUF" &> /dev/null && [ -f "$WORDLIST_DIR/SecLists/Discovery/Web-Content/burp-parameter-names.txt" ]; then
            $FFUF -w "$WORDLIST_DIR/SecLists/Discovery/Web-Content/burp-parameter-names.txt" -u "${url}/index.php?FUZZ=test" -o "$OUTPUT_DIR/web/ffuf_params_${port}.json" -t "$THREADS" &> /dev/null &
        fi
        
        # Nikto scan - skip in fast mode if Nuclei will run
        if command -v "$NIKTO" &> /dev/null && [ "$FAST_MODE" != true ]; then
            $NIKTO -h "$url" -o "$OUTPUT_DIR/web/nikto_${port}.txt" &> /dev/null &
        fi
    done
    
    # Start live monitoring of directory bruteforcing
    monitor_web_dirs &
    local monitor_pid=$!
    
    # Wait for all web scans to complete
    wait
    kill $monitor_pid 2>/dev/null
    
    # Show summary of interesting findings
    echo ""
    echo -e "  ${GREEN}[+] Web reconnaissance completed${NC}"
    
    # Show Nikto findings if any
    if ls "$OUTPUT_DIR/web/nikto_"*.txt 1> /dev/null 2>&1; then
        local nikto_findings=$(grep -h "+ " "$OUTPUT_DIR/web/nikto_"*.txt 2>/dev/null | head -5)
        if [ -n "$nikto_findings" ]; then
            echo ""
            echo -e "  ${YELLOW}[*] Nikto highlights:${NC}"
            echo "$nikto_findings" | while read -r line; do
                print_finding "INTERESTING" "$(echo "$line" | cut -d' ' -f2-)" ""  
            done
        fi
    fi
}

# Run recursive FFUF enumeration as a separate function
run_recursive_ffuf() {
    if [ "$RECURSIVE_FFUF" != true ]; then
        return
    fi
    
    if ! command -v "$FFUF" &> /dev/null || ! command -v jq &> /dev/null; then
        echo ""
        echo -e "  ${RED}[!]${NC} Recursive FFUF requested but requirements not met:"
        command -v "$FFUF" &> /dev/null || echo -e "      ${YELLOW}→${NC} ffuf not found"
        command -v jq &> /dev/null || echo -e "      ${YELLOW}→${NC} jq not found"
        return
    fi
    
    print_section "RECURSIVE DIRECTORY ENUMERATION" "$PURPLE"
    echo -e "  ${BLUE}[*]${NC} Starting recursive FFUF enumeration on discovered directories..."
    echo -e "  ${YELLOW}[*]${NC} This will enumerate subdirectories up to 2 levels deep${NC}"
    echo ""
    
    # Get discovered directories from gobuster results
    local discovered_dirs=()
    for file in "$OUTPUT_DIR/web/gobuster_"*.txt; do
        if [ -f "$file" ]; then
            while IFS= read -r line; do
                local dir=$(echo "$line" | awk '{print $1}' | grep -E "/$" | grep -v "^#")
                if [ -n "$dir" ]; then
                    discovered_dirs+=("$dir")
                fi
            done < <(grep -E "Status: (200|301|302)" "$file" 2>/dev/null | head -10)
        fi
    done
    
    # Remove duplicates
    discovered_dirs=($(printf "%s\n" "${discovered_dirs[@]}" | sort -u))
    
    if [ ${#discovered_dirs[@]} -eq 0 ]; then
        echo -e "  ${YELLOW}[*]${NC} No directories found for recursive enumeration"
        return
    fi
    
    echo -e "  ${GREEN}[+]${NC} Found ${#discovered_dirs[@]} directories to enumerate recursively"
    
    # Re-check which ports have web services
    local web_ports=("80" "443" "8080" "8443" "8000" "3000" "5000")
    for port in "${web_ports[@]}"; do
        if nc -zv "$TARGET" "$port" &> /dev/null; then
            local protocol="http"
            if [ "$port" = "443" ] || [ "$port" = "8443" ]; then
                protocol="https"
            fi
            
            local base_url="${protocol}://${TARGET}:${port}/"
            echo -e "  ${CYAN}[*]${NC} Enumerating on port $port"
            
            for dir in "${discovered_dirs[@]}"; do
                recursive_ffuf_enum "$base_url" "$dir" 1
            done
        fi
    done
}

# Vulnerability scanning
vuln_scan() {
    print_section "VULNERABILITY SCANNING" "$RED"
    
    if ! command -v "$NUCLEI" &> /dev/null; then
        echo -e "  ${YELLOW}[*] Nuclei not found, skipping vulnerability scan${NC}"
        return 1
    fi
    
    echo -e "  ${BLUE}[*]${NC} Running Nuclei scan..."
    echo -e "  ${YELLOW}[*]${NC} Vulnerabilities will appear below as they're found..."
    echo ""
    
    # Start nuclei with live monitoring
    $NUCLEI -target "$TARGET" -o "$OUTPUT_DIR/vulns/nuclei.txt" -c "$THREADS" &> /dev/null &
    local nuclei_pid=$!
    
    # Monitor for vulnerabilities in real-time
    monitor_vulns &
    local monitor_pid=$!
    
    # Wait for nuclei to complete
    wait $nuclei_pid
    sleep 2  # Give monitor a moment to catch final results
    kill $monitor_pid 2>/dev/null
    
    # Final summary
    echo ""
    if [ -f "$OUTPUT_DIR/vulns/nuclei.txt" ]; then
        local vuln_count=$(wc -l < "$OUTPUT_DIR/vulns/nuclei.txt")
        if [ "$vuln_count" -gt 0 ]; then
            echo -e "  ${RED}[!] Found $vuln_count potential vulnerabilities${NC}"
        else
            echo -e "  ${GREEN}[+] No vulnerabilities detected${NC}"
        fi
    fi
}

# Generate summary report
generate_report() {
    log "INFO" "Generating summary report..."
    
    local report_file="$OUTPUT_DIR/recon_summary.txt"
    
    {
        echo "==============================================="
        echo "RECON SUMMARY FOR: $TARGET"
        echo "Generated: $(date)"
        echo "==============================================="
        echo ""
        
        echo "--- SUBDOMAINS ---"
        if [ -f "$OUTPUT_DIR/subdomains/all_subdomains.txt" ]; then
            echo "Total subdomains found: $(wc -l < "$OUTPUT_DIR/subdomains/all_subdomains.txt")"
            echo "Top 10 subdomains:"
            head -10 "$OUTPUT_DIR/subdomains/all_subdomains.txt"
        else
            echo "No subdomains found"
        fi
        echo ""
        
        echo "--- OPEN PORTS ---"
        if [ -f "$OUTPUT_DIR/nmap/quick_scan.txt" ]; then
            grep "open" "$OUTPUT_DIR/nmap/quick_scan.txt" | head -20
        else
            echo "No port scan results"
        fi
        echo ""
        
        echo "--- WEB DIRECTORIES ---"
        if ls "$OUTPUT_DIR/web/gobuster_"*.txt 1> /dev/null 2>&1; then
            echo "Interesting directories found:"
            grep -h "Status: 200\|Status: 301\|Status: 302" "$OUTPUT_DIR/web/gobuster_"*.txt 2>/dev/null | head -20
        else
            echo "No web directories found"
        fi
        echo ""
        
        echo "--- VULNERABILITIES ---"
        if [ -f "$OUTPUT_DIR/vulns/nuclei.txt" ]; then
            local vuln_count=$(wc -l < "$OUTPUT_DIR/vulns/nuclei.txt")
            echo "Nuclei findings: $vuln_count"
            if [ "$vuln_count" -gt 0 ]; then
                echo "Top findings:"
                head -10 "$OUTPUT_DIR/vulns/nuclei.txt"
            fi
        else
            echo "No vulnerability scan results"
        fi
        
    } > "$report_file"
    
    log "SUCCESS" "Summary report generated: $report_file"
}

# Main execution function
main() {
    print_banner
    check_tools
    setup_directories
    
    echo -e "${CYAN}Starting reconnaissance against: $TARGET${NC}"
    echo -e "${YELLOW}Output directory: $OUTPUT_DIR${NC}"
    echo -e "${YELLOW}Threads: $THREADS${NC}"
    echo ""
    
    # Run scans based on options
    if [ "$SUBDOMAIN_ONLY" = true ]; then
        subdomain_enum
    elif [ "$PORT_ONLY" = true ]; then
        port_scan
    elif [ "$WEB_ONLY" = true ]; then
        web_recon
        run_recursive_ffuf
    elif [ "$VULN_ONLY" = true ]; then
        vuln_scan
    else
        # Run all scans
        subdomain_enum
        port_scan
        web_recon
        run_recursive_ffuf
        vuln_scan
    fi
    
    generate_report
    
    # Final summary section
    print_section "RECON COMPLETED" "$GREEN"
    echo -e "  ${GREEN}[+]${NC} All scans completed successfully!"
    echo -e "  ${CYAN}[*]${NC} Results saved in: ${YELLOW}$OUTPUT_DIR${NC}"
    echo -e "  ${CYAN}[*]${NC} Summary report: ${YELLOW}$OUTPUT_DIR/recon_summary.txt${NC}"
    echo ""
    
    # Quick wins section
    print_section "QUICK WINS TO CHECK" "$YELLOW"
    echo -e "  ${YELLOW}[1]${NC} Check for admin panels in web directories"
    echo -e "  ${YELLOW}[2]${NC} Look for default credentials on discovered services"
    echo -e "  ${YELLOW}[3]${NC} Review technology stack for known vulnerabilities"
    echo -e "  ${YELLOW}[4]${NC} Check Nuclei results for immediate exploits"
    echo -e "  ${YELLOW}[5]${NC} Look for backup files (.bak, .old, .backup)"
    echo -e "  ${YELLOW}[6]${NC} Test for common web vulnerabilities (SQLi, XSS, LFI)"
    echo ""
    
    # Show some immediate actionable intel
    if [ -f "$OUTPUT_DIR/nmap/quick_scan.txt" ]; then
        local ssh_port=$(grep "22/tcp.*open" "$OUTPUT_DIR/nmap/quick_scan.txt" | head -1)
        local web_ports=$(grep -E "(80|443|8080|8000|3000|5000)/tcp.*open" "$OUTPUT_DIR/nmap/quick_scan.txt" | wc -l)
        
        if [ -n "$ssh_port" ]; then
            echo -e "  ${CYAN}[*]${NC} SSH detected - try hydra/medusa for brute force"
        fi
        
        if [ "$web_ports" -gt 0 ]; then
            echo -e "  ${CYAN}[*]${NC} $web_ports web service(s) found - check for common paths"
        fi
    fi
    
    # Show top directory findings
    if ls "$OUTPUT_DIR/web/gobuster_"*.txt 1> /dev/null 2>&1; then
        local interesting_dirs=$(grep -h "Status: 200" "$OUTPUT_DIR/web/gobuster_"*.txt 2>/dev/null | head -3)
        if [ -n "$interesting_dirs" ]; then
            echo ""
            echo -e "  ${GREEN}[+] Top accessible directories found:${NC}"
            echo "$interesting_dirs" | while read -r line; do
                local path=$(echo "$line" | awk '{print $1}')
                echo -e "      ${CYAN}→${NC} $path"
            done
        fi
    fi
    
    echo ""
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -o|--output)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        -t|--threads)
            THREADS="$2"
            shift 2
            ;;
        -w|--wordlist)
            WORDLIST_DIR="$2"
            shift 2
            ;;
        --no-check)
            TOOLS_CHECK=false
            shift
            ;;
        --subdomain-only)
            SUBDOMAIN_ONLY=true
            shift
            ;;
        --port-only)
            PORT_ONLY=true
            shift
            ;;
        --web-only)
            WEB_ONLY=true
            shift
            ;;
        --vuln-only)
            VULN_ONLY=true
            shift
            ;;
        -ffuf|--recursive-ffuf)
            RECURSIVE_FFUF=true
            shift
            ;;
        --fast)
            FAST_MODE=true
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        -*)
            echo "Unknown option: $1"
            usage
            exit 1
            ;;
        *)
            if [ -z "$TARGET" ]; then
                TARGET="$1"
            else
                echo "Multiple targets not supported"
                usage
                exit 1
            fi
            shift
            ;;
    esac
done

# Validate required arguments
if [ -z "$TARGET" ]; then
    echo -e "${RED}Error: Target is required${NC}"
    usage
    exit 1
fi

# Set default output directory
if [ -z "$OUTPUT_DIR" ]; then
    OUTPUT_DIR="${TARGET}_recon"
fi

# Run main function
main
