#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
#  phpDetector — PHP Technology Detection Scanner
#  Detects PHP presence via headers & body; extracts version when available.
# ─────────────────────────────────────────────────────────────────────────────

VERSION="1.1.0"

# ── Colors ────────────────────────────────────────────────────────────────────
RED='\033[1;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[1;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

# ── Defaults ──────────────────────────────────────────────────────────────────
LEVEL=1
TARGET=""
THREADS=10
TIMEOUT=10
OUTPUT_FILE=""
ONLY_PHP=0
VERSION_ONLY=0
COOKIE_JAR=""
UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"

# ── Banner ────────────────────────────────────────────────────────────────────
show_banner() {
    echo -e "${RED}"
    echo "  ____  _           ____       _            _             "
    echo " |  _ \| |__  _ __ |  _ \  ___| |_ ___  ___| |_ ___  _ __ "
    echo " | |_) | '_ \| '_ \| | | |/ _ \ __/ _ \/ __| __/ _ \| '__|"
    echo " |  __/| | | | |_) | |_| |  __/ ||  __/ (__| || (_) | |   "
    echo " |_|   |_| |_| .__/|____/ \___|\__\___|\___|\__\___/|_|   "
    echo "              |_|                                           "
    echo -e "${NC}"
    echo -e "  ${DIM}PHP Technology Detection Scanner v${VERSION}${NC}"
    echo ""
}

# ── Help ──────────────────────────────────────────────────────────────────────
show_help() {
    show_banner
    echo -e "${BOLD}USAGE:${NC}"
    echo "  phpDetector -u <url|file> [OPTIONS]"
    echo ""
    echo -e "${BOLD}OPTIONS:${NC}"
    printf "  ${CYAN}%-26s${NC} %s\n" "-u <target>"         "Single URL or path to file containing URLs (one per line)"
    printf "  ${CYAN}%-26s${NC} %s\n" "--level 1"            "Precise: PHPSESSID, .php extensions (default)"
    printf "  ${CYAN}%-26s${NC} %s\n" "--level 2"            "Broad: any 'php' occurrence in headers/body (more noise)"
    printf "  ${CYAN}%-26s${NC} %s\n" "-t <threads>"         "Parallel threads for file mode (default: 10)"
    printf "  ${CYAN}%-26s${NC} %s\n" "--timeout <sec>"      "Per-request timeout seconds (default: 10)"
    printf "  ${CYAN}%-26s${NC} %s\n" "--output <file>"      "Write [PHP DETECTED] results to file (plain text, no ANSI)"
    printf "  ${CYAN}%-26s${NC} %s\n" "--only-php"           "Suppress [NOT PHP] and [SKIP] lines from stdout"
    printf "  ${CYAN}%-26s${NC} %s\n" "--version-only"       "Show only targets where PHP version was extracted"
    printf "  ${CYAN}%-26s${NC} %s\n" "--cookie <cookiejar>" "Cookie jar file to include in requests (Netscape format)"
    printf "  ${CYAN}%-26s${NC} %s\n" "--no-color"           "Disable ANSI color output"
    printf "  ${CYAN}%-26s${NC} %s\n" "-h, --help"           "Show this help menu"
    echo ""
    echo -e "${BOLD}DETECTION LEVELS:${NC}"
    echo "  Level 1  →  grep -Eio 'PHPSESSID|\\.php([/?#\"]|\$)'"
    echo "             → Low false-positive, misses obfuscated installs"
    echo "  Level 2  →  grep -Ein 'php'"
    echo "             → High coverage, expect noise on generic pages"
    echo ""
    echo -e "${BOLD}VERSION EXTRACTION:${NC}"
    echo "  Parsed from response headers:"
    echo "    X-Powered-By: PHP/8.1.27"
    echo "    X-Generator:  PHP/7.4.3"
    echo ""
    echo -e "${BOLD}COOKIE JAR:${NC}"
    echo "  Generate with curl:  curl -c cookies.txt -b cookies.txt https://target.com/login ..."
    echo "  Or export from Burp: Copy cookies as Netscape format"
    echo ""
    echo -e "${BOLD}EXAMPLES:${NC}"
    echo "  phpDetector -u https://example.com"
    echo "  phpDetector -u https://example.com --level 2"
    echo "  phpDetector -u targets.txt --level 1 -t 20"
    echo "  phpDetector -u targets.txt --only-php --output hits.txt"
    echo "  phpDetector -u targets.txt --version-only --output versioned.txt"
    echo "  phpDetector -u targets.txt --cookie session.jar --output results.txt"
    echo "  phpDetector -u targets.txt --no-color | tee results.txt"
    echo ""
}

# ── Normalize URL (add scheme if missing) ─────────────────────────────────────
normalize_url() {
    local url="$1"
    [[ "$url" =~ ^https?:// ]] || url="https://$url"
    echo "$url"
}

# ── Extract PHP version from response headers ─────────────────────────────────
extract_version() {
    local headers="$1"
    grep -Eio 'PHP/[0-9]+\.[0-9]+(\.[0-9]+)?' "$headers" 2>/dev/null \
        | head -1 \
        | grep -Eio '[0-9]+\.[0-9]+(\.[0-9]+)?'
}

# ── Write plain-text hit to output file (thread-safe via >> O_APPEND) ─────────
write_output() {
    local plain_line="$1"
    [[ -n "$OUTPUT_FILE" ]] && printf '%s\n' "$plain_line" >> "$OUTPUT_FILE"
}

# ── Core scan function ────────────────────────────────────────────────────────
scan_url() {
    local raw_url="$1"
    local url
    url=$(normalize_url "$raw_url")

    local tmpdir
    tmpdir=$(mktemp -d)
    local headers="${tmpdir}/headers.txt"
    local body="${tmpdir}/body.html"

    # Build curl command
    local curl_args=(
        -sSL
        -k                          # ignore SSL cert errors
        -D "$headers"
        -o "$body"
        --max-time   "$TIMEOUT"
        --connect-timeout 5
        --max-redirs 5
        --user-agent "$UA"
        -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        -H "Accept-Language: en-US,en;q=0.5"
    )

    # Cookie jar: use -b (send) and -c (receive/update)
    if [[ -n "$COOKIE_JAR" ]]; then
        curl_args+=( -b "$COOKIE_JAR" -c "$COOKIE_JAR" )
    fi

    curl_args+=( "$url" )

    curl "${curl_args[@]}" 2>/dev/null
    local exit_code=$?

    # curl non-zero → connection failure / timeout
    if [[ $exit_code -ne 0 ]]; then
        [[ $ONLY_PHP -eq 0 ]] && echo -e "${DIM}[SKIP] ${url} (curl err: ${exit_code})${NC}"
        rm -rf "$tmpdir"
        return
    fi

    # Apply grep pattern based on level
    local match=""
    if [[ $LEVEL -eq 1 ]]; then
        match=$(grep -Eio 'PHPSESSID|\.php([/?#"]|$)' "$headers" "$body" 2>/dev/null | head -3)
    else
        match=$(grep -Ein 'php' "$headers" "$body" 2>/dev/null | head -3)
    fi

    # Version from response headers (X-Powered-By, X-Generator, etc.)
    local version
    version=$(extract_version "$headers")

    if [[ -n "$match" ]]; then
        # ── --version-only filter ─────────────────────────────────────────────
        # Skip if flag set but no version found
        if [[ $VERSION_ONLY -eq 1 && -z "$version" ]]; then
            rm -rf "$tmpdir"
            return
        fi

        # ── Build stdout line ─────────────────────────────────────────────────
        local colored_line="${RED}[PHP DETECTED]${NC} ${url}"
        local plain_line="[PHP DETECTED] ${url}"

        if [[ -n "$version" ]]; then
            colored_line+=" ${RED}[Version: ${version}]${NC}"
            plain_line+=" [Version: ${version}]"
        fi

        echo -e "$colored_line"

        # Evidence lines (indented)
        while IFS= read -r ev; do
            [[ -n "$ev" ]] && echo -e "   ${DIM}↳ ${ev}${NC}"
        done <<< "$match"

        # Write plain hit to output file
        write_output "$plain_line"

    else
        # ── NOT PHP ───────────────────────────────────────────────────────────
        [[ $ONLY_PHP -eq 0 ]] && echo -e "${GREEN}[NOT PHP   ]${NC} ${url}"
    fi

    rm -rf "$tmpdir"
}

# Export everything needed by xargs subshells
export -f scan_url normalize_url extract_version write_output
export LEVEL TIMEOUT UA OUTPUT_FILE ONLY_PHP VERSION_ONLY COOKIE_JAR
export RED GREEN YELLOW CYAN BOLD DIM NC

# ── Argument parsing ──────────────────────────────────────────────────────────
[[ $# -eq 0 ]] && { show_help; exit 0; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)      show_help; exit 0 ;;
        -u)             TARGET="$2"; shift 2 ;;
        --level)
            LEVEL="$2"
            [[ "$LEVEL" != "1" && "$LEVEL" != "2" ]] && {
                echo -e "${RED}[!]${NC} Invalid level: use 1 or 2"; exit 1
            }
            shift 2 ;;
        -t)             THREADS="$2"; shift 2 ;;
        --timeout)      TIMEOUT="$2"; shift 2 ;;
        --output)
            OUTPUT_FILE="$2"
            # Truncate/create output file upfront
            > "$OUTPUT_FILE" || {
                echo -e "${RED}[!]${NC} Cannot write to output file: $OUTPUT_FILE"; exit 1
            }
            shift 2 ;;
        --only-php)     ONLY_PHP=1; shift ;;
        --version-only) VERSION_ONLY=1; shift ;;
        --cookie)
            COOKIE_JAR="$2"
            [[ ! -f "$COOKIE_JAR" ]] && {
                echo -e "${RED}[!]${NC} Cookie jar not found: $COOKIE_JAR"; exit 1
            }
            shift 2 ;;
        --no-color)
            RED=''; GREEN=''; YELLOW=''; CYAN=''; BOLD=''; DIM=''; NC=''
            export RED GREEN YELLOW CYAN BOLD DIM NC
            shift ;;
        *)
            echo -e "${RED}[!]${NC} Unknown option: $1"
            show_help; exit 1 ;;
    esac
done

[[ -z "$TARGET" ]] && {
    echo -e "${RED}[!]${NC} No target specified. Use -u <url|file>"
    exit 1
}

# Re-export after parsing (values may have changed)
export OUTPUT_FILE ONLY_PHP VERSION_ONLY COOKIE_JAR LEVEL TIMEOUT

show_banner

# ── Run ───────────────────────────────────────────────────────────────────────
if [[ -f "$TARGET" ]]; then
    # ── File mode (parallel) ──────────────────────────────────────────────────
    total=$(grep -cvE '^\s*$|^#' "$TARGET" 2>/dev/null || echo "?")

    echo -e "${BOLD}[*]${NC} Mode         : File scan"
    echo -e "${BOLD}[*]${NC} Target       : ${TARGET} (${total} URLs)"
    echo -e "${BOLD}[*]${NC} Level        : ${LEVEL}"
    echo -e "${BOLD}[*]${NC} Threads      : ${THREADS}"
    echo -e "${BOLD}[*]${NC} Timeout      : ${TIMEOUT}s"
    [[ -n "$OUTPUT_FILE"  ]] && echo -e "${BOLD}[*]${NC} Output file  : ${OUTPUT_FILE}"
    [[ $ONLY_PHP    -eq 1 ]] && echo -e "${BOLD}[*]${NC} Filter       : PHP hits only"
    [[ $VERSION_ONLY -eq 1 ]] && echo -e "${BOLD}[*]${NC} Filter       : Version-only"
    [[ -n "$COOKIE_JAR"   ]] && echo -e "${BOLD}[*]${NC} Cookie jar   : ${COOKIE_JAR}"
    echo ""

    grep -vE '^\s*$|^#' "$TARGET" \
        | xargs -P "$THREADS" -I{} bash -c 'scan_url "$@"' _ {}

elif [[ "$TARGET" =~ ^https?:// ]] || [[ "$TARGET" != *"/"* ]]; then
    # ── Single URL mode ───────────────────────────────────────────────────────
    echo -e "${BOLD}[*]${NC} Mode         : Single URL"
    echo -e "${BOLD}[*]${NC} Target       : ${TARGET}"
    echo -e "${BOLD}[*]${NC} Level        : ${LEVEL}"
    echo -e "${BOLD}[*]${NC} Timeout      : ${TIMEOUT}s"
    [[ -n "$OUTPUT_FILE"  ]] && echo -e "${BOLD}[*]${NC} Output file  : ${OUTPUT_FILE}"
    [[ $VERSION_ONLY -eq 1 ]] && echo -e "${BOLD}[*]${NC} Filter       : Version-only"
    [[ -n "$COOKIE_JAR"   ]] && echo -e "${BOLD}[*]${NC} Cookie jar   : ${COOKIE_JAR}"
    echo ""
    scan_url "$TARGET"

else
    echo -e "${RED}[!]${NC} '${TARGET}' is not a valid URL or readable file."
    exit 1
fi

echo ""

# ── Summary ───────────────────────────────────────────────────────────────────
if [[ -n "$OUTPUT_FILE" && -s "$OUTPUT_FILE" ]]; then
    hit_count=$(wc -l < "$OUTPUT_FILE")
    echo -e "${BOLD}[+]${NC} ${hit_count} PHP hit(s) saved → ${OUTPUT_FILE}"
fi

echo -e "${DIM}[done]${NC}"
