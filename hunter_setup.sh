#!/bin/bash

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

print_header() {
    echo ""
    echo -e "${CYAN}${BOLD}👻 Ghost-Hunter Setup${NC}"
    echo -e "${BLUE}This assistant will prepare the project, ask for the required local config, and print the next steps.${NC}"
    echo ""
}

success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[⚠]${NC} $1"
}

error() {
    echo -e "${RED}[✗]${NC} $1"
}

ask() {
    local prompt="$1"
    local default="${2-}"
    local reply
    if [ -n "$default" ]; then
        read -r -p "$prompt [$default]: " reply
        if [ -z "$reply" ]; then
            reply="$default"
        fi
    else
        read -r -p "$prompt: " reply
    fi
    printf '%s' "$reply"
}

require_command() {
    local cmd="$1"
    local install_hint="$2"
    if ! command -v "$cmd" >/dev/null 2>&1; then
        error "$cmd is required. $install_hint"
        exit 1
    fi
}

prepare_dirs() {
    mkdir -p config data/logs data/pids data/findings data/artifacts data/chains data/flows data/baselines
}

create_venv() {
    require_command python3 "Install Python 3.11+ and retry."

    if [ ! -d "venv" ]; then
        echo -e "${BLUE}Creating virtual environment...${NC}"
        python3 -m venv venv || {
            error "Failed to create virtual environment"
            exit 1
        }
        success "Virtual environment created"
    else
        success "Virtual environment already exists"
    fi

    # shellcheck disable=SC1091
    source venv/bin/activate
    success "Virtual environment activated"
}

install_requirements() {
    local install_profile="${1:-light}"
    local requirements_file="requirements-minimal.txt"

    if [ "${GHOST_HUNTER_SETUP_SKIP_INSTALL:-0}" = "1" ]; then
        warn "Skipping dependency installation because GHOST_HUNTER_SETUP_SKIP_INSTALL=1"
        return
    fi

    if [ "$install_profile" = "full" ] || [ "${GHOST_HUNTER_SETUP_FULL:-0}" = "1" ]; then
        requirements_file="requirements.txt"
    fi

    echo -e "${BLUE}Installing Python dependencies from ${requirements_file}...${NC}"
    python -m pip install --upgrade pip setuptools wheel || {
        error "Failed to upgrade pip tooling"
        exit 1
    }
    python -m pip install -r "$requirements_file" || {
        error "Failed to install requirements"
        if [ "$requirements_file" = "requirements-minimal.txt" ]; then
            warn "The light profile avoids heavy optional RAG packages. For the full stack later, run: ./hunter_setup.sh and choose 'full'"
        fi
        exit 1
    }
    success "Dependencies installed (${requirements_file})"
}

ask_choice() {
    local prompt="$1"
    local default="$2"
    local reply
    while true; do
        read -r -p "$prompt [$default]: " reply
        reply="${reply:-$default}"
        case "$reply" in
            light|LIGHT|Light)
                printf '%s' "light"
                return
                ;;
            full|FULL|Full)
                printf '%s' "full"
                return
                ;;
            *)
                warn "Please answer 'light' or 'full'"
                ;;
        esac
    done
}

ask_yes_no() {
    local prompt="$1"
    local default="$2"
    local reply
    while true; do
        read -r -p "$prompt [$default]: " reply
        reply="${reply:-$default}"
        case "$reply" in
            y|Y|yes|YES|Yes)
                printf '%s' "yes"
                return
                ;;
            n|N|no|NO|No)
                printf '%s' "no"
                return
                ;;
            *)
                warn "Please answer 'y' or 'n'"
                ;;
        esac
    done
}

choose_install_profile() {
    echo -e "${CYAN}${BOLD}Install profile${NC}"
    echo -e "${GREEN}Recommended: light${NC}"
    echo "- smaller install"
    echo "- much less disk usage"
    echo "- faster setup"
    echo "- enough for the public MVP: dashboard, proxy, services, scope UI, API keys, basic AI flow"
    echo ""
    echo "Use full only if you explicitly want the heavy local RAG stack as well:"
    echo "- chromadb"
    echo "- sentence-transformers"
    echo "- langchain and related packages"
    echo ""

    ask_choice "Choose install profile: light or full" "light"
}

write_api_keys() {
    local groq_key="$1"
    local openrouter_key="$2"
    local openai_key="$3"

    python3 - "$groq_key" "$openrouter_key" "$openai_key" <<'PY'
from pathlib import Path
import sys
import yaml

groq_key, openrouter_key, openai_key = sys.argv[1:4]

path = Path("config/api_keys.yaml")
existing = {}
if path.exists():
    existing = yaml.safe_load(path.read_text()) or {}

existing.setdefault("groq", {})
existing.setdefault("openrouter", {})
existing.setdefault("openai", {})

existing["groq"]["api_key"] = groq_key
existing["groq"].setdefault("models", {
    "triage": "llama-3.1-8b-instant",
    "strategy": "llama-3.3-70b-versatile",
})

existing["openrouter"]["api_key"] = openrouter_key
existing["openrouter"].setdefault("models", {
    "triage": "anthropic/claude-3.5-haiku",
    "strategy": "anthropic/claude-3.5-sonnet",
})

existing["openai"]["api_key"] = openai_key
existing["openai"].setdefault("model", "text-embedding-3-small")

path.write_text(yaml.safe_dump(existing, sort_keys=False))
PY
}

write_scope() {
    local target_name="$1"
    local program_url="$2"
    local in_scope_csv="$3"
    local out_scope_csv="$4"
    local notes="$5"

    python3 - "$target_name" "$program_url" "$in_scope_csv" "$out_scope_csv" "$notes" <<'PY'
from pathlib import Path
import json
import sys

target_name, program_url, in_scope_csv, out_scope_csv, notes = sys.argv[1:6]

def split_csv(value: str):
    return [item.strip() for item in value.split(",") if item.strip()]

scope = {
    "target": {
        "name": target_name,
        "program_url": program_url,
    },
    "in_scope": split_csv(in_scope_csv),
    "out_of_scope": split_csv(out_scope_csv),
    "notes": notes,
}

Path("config/scope.json").write_text(json.dumps(scope, indent=2))
PY
}

configure_scope() {
    echo ""
    echo -e "${CYAN}${BOLD}Scope mode${NC}"
    echo "By default, Ghost-Hunter will accept what the Burp plugin sends."
    echo "Recommended public setup: let Burp scope be the main filter."
    echo ""

    local use_burp_scope_only
    use_burp_scope_only="$(ask_yes_no "Use Burp scope only and accept all Burp-scoped traffic?" "y")"

    local target_name
    local program_url
    local in_scope_csv
    local out_scope_csv
    local notes

    if [ "$use_burp_scope_only" = "yes" ]; then
        target_name="$(ask "Program / target name" "Burp-scoped target")"
        program_url="$(ask "Program URL" "")"
        in_scope_csv="*"
        out_scope_csv=""
        notes="Using Burp scope as the main source of truth. Ghost-Hunter accepts traffic forwarded by the Burp plugin."
        write_scope "$target_name" "$program_url" "$in_scope_csv" "$out_scope_csv" "$notes"
        success "Saved scope config in Burp-scope mode (all Burp-scoped traffic accepted)"
        return
    fi

    echo -e "${CYAN}${BOLD}Custom Ghost-Hunter scope${NC}"
    target_name="$(ask "Program / target name" "Example Program")"
    program_url="$(ask "Program URL" "https://example.com/bug-bounty")"
    in_scope_csv="$(ask "In-scope patterns (comma-separated)" "api.example.com,*.example.com,*/api/*")"
    out_scope_csv="$(ask "Out-of-scope patterns (comma-separated)" "*.google.com,*.googleapis.com,*.gstatic.com,*.facebook.com,*.twitter.com,*.segment.io,*.sentry.io")"
    notes="$(ask "Notes" "Replace with your own authorized target scope before testing.")"
    write_scope "$target_name" "$program_url" "$in_scope_csv" "$out_scope_csv" "$notes"
    success "Saved custom Ghost-Hunter scope config to config/scope.json"
}

show_optional_hints() {
    echo ""
    echo -e "${GREEN}${BOLD}🚀 Ghost-Hunter is ready!${NC}"
    echo ""
    echo "Tips:"
    echo "  • Configure ton navigateur proxy: 127.0.0.1:8888"
    echo "  • Dashboard: http://127.0.0.1:1010/dashboard"
    echo "  • Plugin Burp guide: http://127.0.0.1:1010/dashboard#/burpguide"
    echo "  • Logs: tail -f $SCRIPT_DIR/data/logs/*.log"
    echo "  • Stop: $SCRIPT_DIR/hunt.sh stop"
    echo ""
    echo -e "${YELLOW}Android note:${NC} set the device proxy to your workstation IP on port 8888, install the interception CA if needed, and use your approved pinning bypass workflow outside the UI when required."
    echo ""
    echo "Last step: branche le plugin Burp et suis le guide local: http://127.0.0.1:1010/dashboard#/burpguide"
    echo ""
}

main() {
    print_header
    prepare_dirs
    create_venv

    local install_profile
    install_profile="$(choose_install_profile)"
    install_requirements "$install_profile"

    echo -e "${CYAN}${BOLD}API providers${NC}"
    local groq_key
    local openrouter_key
    local openai_key
    groq_key="$(ask "Groq API key (recommended)" "")"
    openrouter_key="$(ask "OpenRouter API key (optional fallback)" "")"
    openai_key="$(ask "OpenAI API key (optional, for RAG/embeddings)" "")"
    write_api_keys "$groq_key" "$openrouter_key" "$openai_key"
    success "Saved local API key config to config/api_keys.yaml"

    configure_scope

    echo ""
    if command -v redis-server >/dev/null 2>&1; then
        success "redis-server detected"
    else
        warn "redis-server not found. The app can still run with in-memory fallback, but Redis is recommended. Install with: sudo apt install redis-server"
    fi

    if ! command -v mitmdump >/dev/null 2>&1; then
        warn "mitmdump not found in PATH. It should be available after requirements install inside venv. If needed, run: source venv/bin/activate"
    else
        success "mitmdump detected"
    fi

    show_optional_hints

    local start_now
    start_now="$(ask_yes_no "Start Ghost-Hunter now?" "y")"
    if [ "$start_now" = "yes" ]; then
        echo ""
        echo "➡️  Avant utilisation: branche le plugin Burp et suis le guide: http://127.0.0.1:1010/dashboard#/burpguide"
        exec "$SCRIPT_DIR/hunt.sh" start
    fi
}

main "$@"