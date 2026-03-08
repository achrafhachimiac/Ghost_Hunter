#!/bin/bash
# Ghost-Hunter Knowledge Base Setup
# Downloads and organizes external security resources

set -e

KNOWLEDGE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$KNOWLEDGE_DIR"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[✓]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[!]${NC} $1"; }
log_error() { echo -e "${RED}[✗]${NC} $1"; }

# ============================================================
# HackTricks - Bible du pentester
# ============================================================
setup_hacktricks() {
    log_info "Setting up HackTricks..."
    
    if [ -d "hacktricks/.git" ]; then
        log_info "Updating HackTricks..."
        cd hacktricks && git pull --quiet && cd ..
    else
        log_info "Cloning HackTricks (this may take a while)..."
        rm -rf hacktricks
        git clone --depth 1 https://github.com/carlospolop/hacktricks.git hacktricks
    fi
    
    # Create index for fast search
    log_info "Creating search index..."
    find hacktricks -name "*.md" -type f > hacktricks/.file_index
    
    log_success "HackTricks ready ($(wc -l < hacktricks/.file_index) files)"
}

# ============================================================
# PayloadsAllTheThings - Payloads organisés par vuln
# ============================================================
setup_payloads() {
    log_info "Setting up PayloadsAllTheThings..."
    
    if [ -d "payloads/.git" ]; then
        log_info "Updating PayloadsAllTheThings..."
        cd payloads && git pull --quiet && cd ..
    else
        log_info "Cloning PayloadsAllTheThings..."
        rm -rf payloads
        git clone --depth 1 https://github.com/swisskyrepo/PayloadsAllTheThings.git payloads
    fi
    
    # Create organized structure
    mkdir -p payloads/_organized
    
    log_success "PayloadsAllTheThings ready"
}

# ============================================================
# SecLists + Assetnote Wordlists
# ============================================================
setup_wordlists() {
    log_info "Setting up Wordlists..."
    mkdir -p wordlists
    
    # SecLists (selective - not the full 1GB)
    log_info "Downloading essential SecLists..."
    
    SECLISTS_BASE="https://raw.githubusercontent.com/danielmiessler/SecLists/master"
    
    mkdir -p wordlists/discovery wordlists/fuzzing wordlists/passwords
    
    # API Discovery
    curl -sL "$SECLISTS_BASE/Discovery/Web-Content/api/api-endpoints.txt" -o wordlists/discovery/api-endpoints.txt 2>/dev/null || true
    curl -sL "$SECLISTS_BASE/Discovery/Web-Content/common.txt" -o wordlists/discovery/common.txt 2>/dev/null || true
    curl -sL "$SECLISTS_BASE/Discovery/Web-Content/raft-large-directories.txt" -o wordlists/discovery/raft-large-directories.txt 2>/dev/null || true
    
    # Fuzzing
    curl -sL "$SECLISTS_BASE/Fuzzing/special-chars.txt" -o wordlists/fuzzing/special-chars.txt 2>/dev/null || true
    curl -sL "$SECLISTS_BASE/Fuzzing/SQLi/Generic-SQLi.txt" -o wordlists/fuzzing/sqli.txt 2>/dev/null || true
    curl -sL "$SECLISTS_BASE/Fuzzing/XSS/XSS-Jhaddix.txt" -o wordlists/fuzzing/xss.txt 2>/dev/null || true
    curl -sL "$SECLISTS_BASE/Fuzzing/LFI/LFI-Jhaddix.txt" -o wordlists/fuzzing/lfi.txt 2>/dev/null || true
    
    # Passwords
    curl -sL "$SECLISTS_BASE/Passwords/Common-Credentials/10k-most-common.txt" -o wordlists/passwords/10k-common.txt 2>/dev/null || true
    
    # Assetnote Wordlists (ML-generated, better quality)
    log_info "Downloading Assetnote wordlists..."
    ASSETNOTE_BASE="https://wordlists-cdn.assetnote.io/data"
    
    mkdir -p wordlists/assetnote
    curl -sL "$ASSETNOTE_BASE/manual/best-dns-wordlist.txt" -o wordlists/assetnote/dns.txt 2>/dev/null || true
    curl -sL "$ASSETNOTE_BASE/automated/httparchive_apiroutes_2024_11_28.txt" -o wordlists/assetnote/api-routes.txt 2>/dev/null || true
    curl -sL "$ASSETNOTE_BASE/automated/httparchive_parameters_top_1m_2024_11_28.txt" -o wordlists/assetnote/parameters.txt 2>/dev/null || true
    
    log_success "Wordlists ready"
}

# ============================================================
# Nuclei Templates
# ============================================================
setup_nuclei() {
    log_info "Setting up Nuclei Templates..."
    
    if [ -d "nuclei-templates/.git" ]; then
        log_info "Updating Nuclei Templates..."
        cd nuclei-templates && git pull --quiet && cd ..
    else
        log_info "Cloning Nuclei Templates..."
        rm -rf nuclei-templates
        git clone --depth 1 https://github.com/projectdiscovery/nuclei-templates.git nuclei-templates
    fi
    
    # Count templates
    TEMPLATE_COUNT=$(find nuclei-templates -name "*.yaml" -type f | wc -l)
    log_success "Nuclei Templates ready ($TEMPLATE_COUNT templates)"
}

# ============================================================
# Cheatsheets
# ============================================================
setup_cheatsheets() {
    log_info "Setting up Cheatsheets..."
    mkdir -p cheatsheets
    
    # Bug Bounty Cheatsheet
    if [ -d "cheatsheets/bug-bounty-cheatsheet/.git" ]; then
        cd cheatsheets/bug-bounty-cheatsheet && git pull --quiet && cd ../..
    else
        rm -rf cheatsheets/bug-bounty-cheatsheet
        git clone --depth 1 https://github.com/EdOverflow/bugbounty-cheatsheet.git cheatsheets/bug-bounty-cheatsheet 2>/dev/null || true
    fi
    
    # OWASP Cheatsheets
    if [ -d "cheatsheets/owasp/.git" ]; then
        cd cheatsheets/owasp && git pull --quiet && cd ../..
    else
        rm -rf cheatsheets/owasp
        git clone --depth 1 https://github.com/OWASP/CheatSheetSeries.git cheatsheets/owasp 2>/dev/null || true
    fi
    
    log_success "Cheatsheets ready"
}

# ============================================================
# Business Logic Patterns
# ============================================================
setup_patterns() {
    log_info "Setting up Business Logic Patterns..."
    mkdir -p patterns
    
    # Create pattern files
    cat > patterns/authentication.yaml << 'EOF'
# Authentication Vulnerability Patterns
name: authentication
description: Patterns for authentication bypass and weaknesses

patterns:
  - name: password_reset_token_leak
    indicators:
      - "password_reset"
      - "forgot_password"
      - "reset_token"
    test_cases:
      - "Token in URL parameters"
      - "Token in response body"
      - "Predictable token generation"
      
  - name: session_fixation
    indicators:
      - "session"
      - "JSESSIONID"
      - "PHPSESSID"
    test_cases:
      - "Session ID unchanged after login"
      - "Session ID in URL"
      
  - name: oauth_misconfig
    indicators:
      - "oauth"
      - "redirect_uri"
      - "callback"
      - "state"
    test_cases:
      - "Open redirect in callback"
      - "Missing state parameter"
      - "Token leakage via referrer"
      
  - name: jwt_weaknesses
    indicators:
      - "Bearer"
      - "eyJ"
      - "jwt"
    test_cases:
      - "Algorithm confusion (none/HS256)"
      - "Weak secret key"
      - "Missing expiration"
EOF

    cat > patterns/idor.yaml << 'EOF'
# IDOR Vulnerability Patterns
name: idor
description: Insecure Direct Object Reference patterns

patterns:
  - name: numeric_id
    indicators:
      - "id="
      - "user_id"
      - "account_id"
      - "order_id"
    test_cases:
      - "Increment/decrement ID"
      - "Use other user's ID"
      - "Negative ID values"
      
  - name: uuid_enumeration
    indicators:
      - "uuid"
      - "[a-f0-9]{8}-[a-f0-9]{4}"
    test_cases:
      - "UUID from other endpoints"
      - "Predictable UUID generation"
      
  - name: file_reference
    indicators:
      - "filename"
      - "file_id"
      - "document"
      - "attachment"
    test_cases:
      - "Path traversal"
      - "Other user's files"
EOF

    cat > patterns/business_logic.yaml << 'EOF'
# Business Logic Vulnerability Patterns
name: business_logic
description: Business logic flaw patterns

patterns:
  - name: race_condition
    indicators:
      - "balance"
      - "quantity"
      - "amount"
      - "coupon"
      - "discount"
    test_cases:
      - "Concurrent requests"
      - "Double spending"
      - "Race on limited resources"
      
  - name: price_manipulation
    indicators:
      - "price"
      - "total"
      - "amount"
      - "cost"
    test_cases:
      - "Negative price"
      - "Zero price"
      - "Decimal manipulation"
      - "Currency confusion"
      
  - name: workflow_bypass
    indicators:
      - "step"
      - "stage"
      - "status"
      - "state"
    test_cases:
      - "Skip verification step"
      - "Direct final step access"
      - "State manipulation"
      
  - name: privilege_escalation
    indicators:
      - "role"
      - "admin"
      - "privilege"
      - "permission"
    test_cases:
      - "Role parameter manipulation"
      - "Hidden admin endpoints"
      - "Mass assignment"
EOF

    cat > patterns/api.yaml << 'EOF'
# API Security Patterns
name: api
description: API vulnerability patterns

patterns:
  - name: mass_assignment
    indicators:
      - "PUT"
      - "PATCH"
      - "POST"
      - "role"
      - "admin"
      - "verified"
    test_cases:
      - "Add admin=true to request"
      - "Add role=admin"
      - "Add verified=true"
      
  - name: graphql_introspection
    indicators:
      - "graphql"
      - "__schema"
      - "query"
    test_cases:
      - "Introspection query"
      - "Batch query abuse"
      - "Nested query DoS"
      
  - name: api_versioning
    indicators:
      - "/v1/"
      - "/v2/"
      - "/api/"
    test_cases:
      - "Access old API versions"
      - "Version header manipulation"
      
  - name: rate_limit_bypass
    indicators:
      - "X-Forwarded-For"
      - "X-Real-IP"
      - "X-Originating-IP"
    test_cases:
      - "Header manipulation"
      - "IP rotation"
      - "Endpoint variation"
EOF

    log_success "Business Logic Patterns ready"
}

# ============================================================
# Main
# ============================================================
show_usage() {
    echo "Usage: $0 [component]"
    echo ""
    echo "Components:"
    echo "  all          - Install everything (default)"
    echo "  hacktricks   - HackTricks pentesting bible"
    echo "  payloads     - PayloadsAllTheThings"
    echo "  wordlists    - SecLists + Assetnote"
    echo "  nuclei       - Nuclei templates"
    echo "  cheatsheets  - Bug bounty cheatsheets"
    echo "  patterns     - Business logic patterns"
    echo ""
    echo "Example:"
    echo "  $0 all"
    echo "  $0 wordlists"
}

main() {
    echo ""
    echo "╔═══════════════════════════════════════════════════════╗"
    echo "║     👻 Ghost-Hunter Knowledge Base Setup              ║"
    echo "╚═══════════════════════════════════════════════════════╝"
    echo ""
    
    COMPONENT="${1:-all}"
    
    case "$COMPONENT" in
        all)
            setup_patterns      # Quick, no download
            setup_wordlists     # Essential wordlists
            setup_cheatsheets   # Bug bounty cheatsheets
            setup_payloads      # PayloadsAllTheThings
            setup_nuclei        # Nuclei templates
            setup_hacktricks    # HackTricks (largest)
            ;;
        hacktricks)
            setup_hacktricks
            ;;
        payloads)
            setup_payloads
            ;;
        wordlists)
            setup_wordlists
            ;;
        nuclei)
            setup_nuclei
            ;;
        cheatsheets)
            setup_cheatsheets
            ;;
        patterns)
            setup_patterns
            ;;
        -h|--help|help)
            show_usage
            exit 0
            ;;
        *)
            log_error "Unknown component: $COMPONENT"
            show_usage
            exit 1
            ;;
    esac
    
    echo ""
    log_success "Knowledge Base setup complete!"
    echo ""
    
    # Show disk usage
    echo "📊 Disk usage:"
    du -sh */ 2>/dev/null | sort -h
}

main "$@"
