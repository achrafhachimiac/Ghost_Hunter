#!/bin/bash
# ╔═══════════════════════════════════════════════════════════════════════╗
# ║  👻 GHOST-HUNTER - AI-Powered Bug Bounty Command Center               ║
# ║  Service Launcher v3.0 - Robust Edition                               ║
# ╚═══════════════════════════════════════════════════════════════════════╝

# Ne PAS utiliser set -e pour permettre la gestion manuelle des erreurs
# set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ==================== Couleurs ====================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
WHITE='\033[1;37m'
BOLD='\033[1m'
NC='\033[0m'

# ==================== Configuration ====================
REDIS_PORT=6379
PROXY_PORT=8888
DASHBOARD_PORT=1010
OOB_PORT=9999

LOG_DIR="$SCRIPT_DIR/data/logs"
PID_DIR="$SCRIPT_DIR/data/pids"

# Fichiers PID
REDIS_PID="$PID_DIR/redis.pid"
PROXY_PID="$PID_DIR/proxy.pid"
DASHBOARD_PID="$PID_DIR/dashboard.pid"
OOB_PID="$PID_DIR/oob.pid"

# ==================== Functions ====================

print_banner() {
    clear
    echo ""
    echo -e "${WHITE}          ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗${NC}"
    echo -e "${WHITE}         ██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝${NC}"
    echo -e "${WHITE}         ██║  ███╗███████║██║   ██║███████╗   ██║   ${NC}"
    echo -e "${WHITE}         ██║   ██║██╔══██║██║   ██║╚════██║   ██║   ${NC}"
    echo -e "${WHITE}         ╚██████╔╝██║  ██║╚██████╔╝███████║   ██║   ${NC}"
    echo -e "${WHITE}          ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝   ${NC}"
    echo ""
    echo -e "${CYAN}         ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ ${NC}"
    echo -e "${CYAN}         ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗${NC}"
    echo -e "${CYAN}         ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝${NC}"
    echo -e "${CYAN}         ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗${NC}"
    echo -e "${CYAN}         ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║${NC}"
    echo -e "${CYAN}         ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝${NC}"
    echo ""
    echo -e "${GREEN}              ═══ AI-Powered Bug Bounty Automation ═══${NC}"
    echo ""
    echo -e "${BLUE}                                              Public Edition${NC}"
    echo ""
    echo -e "${YELLOW}  ════════════════════════════════════════════════════════════════════${NC}"
    echo ""
}

log() {
    echo -e "${BLUE}[$(date '+%H:%M:%S')]${NC} $1"
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

# Création des dossiers nécessaires
setup_dirs() {
    mkdir -p "$LOG_DIR" "$PID_DIR"
    mkdir -p data/findings data/artifacts data/chains data/flows data/baselines
}

# Vérifier si un port est utilisé
is_port_used() {
    local port=$1
    if command -v lsof &> /dev/null; then
        lsof -i ":$port" &> /dev/null
    elif command -v ss &> /dev/null; then
        ss -tuln | grep -q ":$port "
    elif command -v netstat &> /dev/null; then
        netstat -tuln | grep -q ":$port "
    else
        return 1
    fi
}

# Activer venv
activate_venv() {
    if [ -d "venv" ]; then
        source venv/bin/activate
        success "Virtual environment activé"
    else
        error "venv non trouvé! Lance d'abord ./hunter_setup.sh"
        exit 1
    fi
}

# ==================== Service Control Functions ====================

start_redis() {
    echo ""
    log "${BOLD}Starting Redis..."
    
    if is_port_used $REDIS_PORT; then
        if redis-cli ping &> /dev/null 2>&1; then
            success "Redis déjà en cours sur le port $REDIS_PORT"
            return 0
        else
            warn "Port $REDIS_PORT utilisé par un autre processus"
            return 1
        fi
    fi
    
    if command -v redis-server &> /dev/null; then
        redis-server --daemonize yes --port $REDIS_PORT \
            --logfile "$LOG_DIR/redis.log" \
            --dir "$SCRIPT_DIR/data" 2>&1
        
        sleep 1
        if redis-cli ping &> /dev/null 2>&1; then
            success "Redis démarré sur le port $REDIS_PORT"
            pgrep -f "redis-server.*$REDIS_PORT" > "$REDIS_PID" 2>/dev/null || true
            return 0
        else
            error "Échec du démarrage de Redis"
            return 1
        fi
    else
        warn "Redis non installé - déduplication en mémoire uniquement"
        warn "Installe avec: sudo apt install redis-server"
        return 1
    fi
}

start_dashboard() {
    echo ""
    log "${BOLD}Starting Dashboard API..."
    
    # Force kill any existing dashboard
    pkill -9 -f "uvicorn dashboard.api" 2>/dev/null || true
    sleep 1
    
    # Libérer le port si occupé
    if is_port_used $DASHBOARD_PORT; then
        warn "Port $DASHBOARD_PORT occupé, tentative de libération..."
        fuser -k $DASHBOARD_PORT/tcp 2>/dev/null || true
        sleep 2
    fi
    
    # Vérifier que le module existe
    if [ ! -f "dashboard/api.py" ]; then
        error "Dashboard API non trouvé: dashboard/api.py"
        return 1
    fi
    
    log "Commande: uvicorn dashboard.api:app --host 0.0.0.0 --port $DASHBOARD_PORT"
    
    nohup python -m uvicorn dashboard.api:app \
        --host 0.0.0.0 \
        --port $DASHBOARD_PORT \
        > "$LOG_DIR/dashboard.log" 2>&1 &
    
    local dashboard_pid=$!
    echo $dashboard_pid > "$DASHBOARD_PID"
    
    # Attendre et vérifier
    local attempts=0
    local max_attempts=5
    while [ $attempts -lt $max_attempts ]; do
        sleep 1
        attempts=$((attempts + 1))
        
        if ! kill -0 $dashboard_pid 2>/dev/null; then
            error "Le dashboard s'est arrêté prématurément"
            echo "=== Dernières lignes du log ===" 
            tail -20 "$LOG_DIR/dashboard.log" 2>/dev/null || echo "(log vide)"
            return 1
        fi
        
        if is_port_used $DASHBOARD_PORT; then
            success "Dashboard démarré sur http://127.0.0.1:$DASHBOARD_PORT (PID: $dashboard_pid)"
            return 0
        fi
        
        log "Attente du dashboard... ($attempts/$max_attempts)"
    done
    
    error "Échec du démarrage du Dashboard après ${max_attempts}s"
    tail -20 "$LOG_DIR/dashboard.log" 2>/dev/null || true
    return 1
}

start_proxy() {
    echo ""
    log "${BOLD}Starting Proxy..."
    
    # Force kill any existing proxy
    pkill -9 -f "mitmdump.*proxy.py" 2>/dev/null || true
    sleep 1
    
    # Libérer le port si occupé
    if is_port_used $PROXY_PORT; then
        warn "Port $PROXY_PORT occupé, tentative de libération..."
        fuser -k $PROXY_PORT/tcp 2>/dev/null || true
        sleep 2
    fi
    
    # Vérifier que mitmdump est disponible
    if ! command -v mitmdump &> /dev/null; then
        error "mitmdump non trouvé! Installe avec: pip install mitmproxy"
        return 1
    fi
    
    # Vérifier que le script proxy existe
    if [ ! -f "ghost_hunter/core/interceptor/proxy.py" ]; then
        error "Script proxy non trouvé: ghost_hunter/core/interceptor/proxy.py"
        return 1
    fi
    
    # Lancer le proxy avec plus de verbosité dans les logs
    log "Commande: mitmdump -s ghost_hunter/core/interceptor/proxy.py -p $PROXY_PORT"
    
    nohup mitmdump \
        -s ghost_hunter/core/interceptor/proxy.py \
        -p $PROXY_PORT \
        --set ssl_insecure=true \
        --set block_global=false \
        > "$LOG_DIR/proxy.log" 2>&1 &
    
    local proxy_pid=$!
    echo $proxy_pid > "$PROXY_PID"
    
    # Attendre et vérifier plusieurs fois
    local attempts=0
    local max_attempts=5
    while [ $attempts -lt $max_attempts ]; do
        sleep 1
        attempts=$((attempts + 1))
        
        # Vérifier si le process existe encore
        if ! kill -0 $proxy_pid 2>/dev/null; then
            error "Le proxy s'est arrêté prématurément"
            echo "=== Dernières lignes du log ===" 
            tail -20 "$LOG_DIR/proxy.log" 2>/dev/null || echo "(log vide)"
            return 1
        fi
        
        # Vérifier si le port est ouvert
        if is_port_used $PROXY_PORT; then
            success "Proxy démarré sur http://127.0.0.1:$PROXY_PORT (PID: $proxy_pid)"
            return 0
        fi
        
        log "Attente du proxy... ($attempts/$max_attempts)"
    done
    
    error "Échec du démarrage du Proxy après ${max_attempts}s"
    echo "=== Log complet ===" 
    cat "$LOG_DIR/proxy.log" 2>/dev/null || echo "(log vide)"
    return 1
}

start_oob() {
    echo ""
    log "${BOLD}Starting OOB Listener..."
    
    if is_port_used $OOB_PORT; then
        warn "OOB port $OOB_PORT déjà utilisé"
        return 1
    fi
    
    # Lancer le OOB handler s'il existe
    if [ -f "ghost_hunter/core/oob/handler.py" ]; then
        # OOB Callback Handler est géré par le pipeline, pas besoin de serveur séparé
        echo "OOB callbacks managed internally by pipeline" > "$LOG_DIR/oob.log"
        success "OOB Callback Handler intégré au pipeline"
        return 0
    else
        warn "OOB handler non trouvé"
        return 1
    fi
}

# ==================== Stop Functions ====================

stop_service() {
    local name=$1
    local pid_file=$2
    
    if [ -f "$pid_file" ]; then
        local pid=$(cat "$pid_file")
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null
            success "$name arrêté (PID: $pid)"
        fi
        rm -f "$pid_file"
    fi
}

force_stop_all() {
    echo ""
    log "${BOLD}🔪 Force stop de tous les services..."
    
    # Kill agressif par pattern (avec sudo si disponible)
    sudo pkill -9 -f "mitmdump.*proxy.py" 2>/dev/null || pkill -9 -f "mitmdump.*proxy.py" 2>/dev/null || true
    sudo pkill -9 -f "mitmdump.*8888" 2>/dev/null || pkill -9 -f "mitmdump.*8888" 2>/dev/null || true
    sudo pkill -9 -f "uvicorn dashboard" 2>/dev/null || pkill -9 -f "uvicorn dashboard" 2>/dev/null || true
    sudo pkill -9 -f "uvicorn.*1010" 2>/dev/null || pkill -9 -f "uvicorn.*1010" 2>/dev/null || true
    pkill -9 -f "OOBHandler" 2>/dev/null || true
    
    # Libérer les ports par force (avec sudo)
    sudo fuser -k 1010/tcp 2>/dev/null || fuser -k 1010/tcp 2>/dev/null || true
    sudo fuser -k 8888/tcp 2>/dev/null || fuser -k 8888/tcp 2>/dev/null || true
    sudo fuser -k 9999/tcp 2>/dev/null || fuser -k 9999/tcp 2>/dev/null || true
    
    # Nettoyer les PID files
    rm -f "$PROXY_PID" "$DASHBOARD_PID" "$OOB_PID" 2>/dev/null || true
    
    sleep 2
    
    # Vérifier que les ports sont libres
    local all_clear=true
    if lsof -i :8888 &>/dev/null; then
        warn "Port 8888 toujours occupé!"
        lsof -i :8888
        all_clear=false
    fi
    if lsof -i :1010 &>/dev/null; then
        warn "Port 1010 toujours occupé!"
        all_clear=false
    fi
    
    if [ "$all_clear" = true ]; then
        success "Force stop terminé - tous les ports sont libres"
    else
        error "Certains ports sont encore occupés. Essaie: sudo ./start.sh nuke"
    fi
}

stop_all() {
    echo ""
    log "${BOLD}Arrêt de tous les services..."
    
    # Arrêter via PID files
    stop_service "Proxy" "$PROXY_PID"
    stop_service "Dashboard" "$DASHBOARD_PID"
    stop_service "OOB Listener" "$OOB_PID"
    
    # Kill par pattern (backup)
    pkill -f "mitmdump.*proxy.py" 2>/dev/null || true
    pkill -f "uvicorn dashboard" 2>/dev/null || true
    pkill -f "OOBHandler" 2>/dev/null || true
    
    # Redis (ne pas tuer par défaut car peut être utilisé par d'autres)
    if [ -f "$REDIS_PID" ]; then
        local redis_pid=$(cat "$REDIS_PID")
        if kill -0 "$redis_pid" 2>/dev/null; then
            redis-cli shutdown 2>/dev/null || kill "$redis_pid" 2>/dev/null || true
            success "Redis arrêté"
        fi
        rm -f "$REDIS_PID"
    fi
    
    success "Tous les services Ghost-Hunter sont arrêtés"
}

# ==================== Status Function ====================

show_status() {
    echo ""
    echo -e "${BOLD}============= SERVICE STATUS =============${NC}"
    echo ""
    
    # Redis
    if redis-cli ping &> /dev/null 2>&1; then
        echo -e "  ${GREEN}[OK]${NC}  Redis         :$REDIS_PORT"
    else
        echo -e "  ${RED}[--]${NC}  Redis         STOPPED"
    fi
    
    # Dashboard
    if is_port_used $DASHBOARD_PORT; then
        echo -e "  ${GREEN}[OK]${NC}  Dashboard     :$DASHBOARD_PORT"
    else
        echo -e "  ${RED}[--]${NC}  Dashboard     STOPPED"
    fi
    
    # Proxy
    if is_port_used $PROXY_PORT; then
        echo -e "  ${GREEN}[OK]${NC}  Proxy         :$PROXY_PORT"
    else
        echo -e "  ${RED}[--]${NC}  Proxy         STOPPED"
    fi
    
    # OOB
    if is_port_used $OOB_PORT; then
        echo -e "  ${GREEN}[OK]${NC}  OOB Listener  :$OOB_PORT"
    else
        echo -e "  ${YELLOW}[--]${NC}  OOB Listener  OPTIONAL"
    fi
    
    echo ""
    echo -e "===========================================${NC}"
    echo ""
    echo -e "${CYAN}Dashboard URL:${NC}  http://127.0.0.1:$DASHBOARD_PORT/dashboard"
    echo -e "${CYAN}Proxy Config:${NC}   http://127.0.0.1:$PROXY_PORT"
    echo ""
}

show_config() {
    echo ""
    echo -e "${MAGENTA}${BOLD}Target Configuration:${NC}"
    if [ -f "config/scope.json" ]; then
        python3 -c "
import json
with open('config/scope.json') as f:
    d = json.load(f)
    target = d.get('target', {})
    in_scope = d.get('in_scope', [])
    print(f\"  Name: {target.get('name', 'Unknown')}\")
    print(f\"  Platform: {target.get('platform', 'N/A')}\")
    print(f\"  In-scope domains: {len(in_scope)}\")
    for domain in in_scope[:5]:
        print(f\"    • {domain}\")
    if len(in_scope) > 5:
        print(f\"    ... and {len(in_scope) - 5} more\")
"
    else
        warn "config/scope.json non trouvé"
    fi
    echo ""
}

# ==================== Start All ====================

start_all() {
    print_banner
    
    setup_dirs
    activate_venv
    show_config
    
    echo -e "${BOLD}${CYAN}Starting all services...${NC}"
    echo ""
    
    # 1. Redis
    start_redis
    
    # 2. Dashboard
    start_dashboard
    
    # 3. Proxy
    start_proxy
    
    # 4. OOB (optionnel)
    start_oob || true
    
    # Status final
    show_status
    
    echo ""
    echo -e "${GREEN}${BOLD}🚀 Ghost-Hunter is ready!${NC}"
    echo ""
    echo -e "${YELLOW}Tips:${NC}"
    echo "  • Configure ton navigateur proxy: 127.0.0.1:$PROXY_PORT"
    echo "  • Dashboard: http://127.0.0.1:$DASHBOARD_PORT/dashboard"
    echo "  • Guide plugin Burp: http://127.0.0.1:$DASHBOARD_PORT/dashboard#/burpguide"
    echo "  • Logs: tail -f $LOG_DIR/*.log"
    echo "  • Stop: $0 stop"
    echo ""
    echo -e "${CYAN}${BOLD}Next required step:${NC}"
    echo "  1. Branche le plugin Burp Ghost-Hunter dans Burp Suite"
    echo "  2. Suis le guide local: http://127.0.0.1:$DASHBOARD_PORT/dashboard#/burpguide"
    echo "  3. Configure ton scope dans Burp (Target -> Scope)"
    echo "  4. Commence à générer du trafic dans Burp en naviguant l'application cible"
    echo ""
}

# ==================== Foreground Mode ====================

start_foreground() {
    print_banner
    setup_dirs
    activate_venv
    show_config
    
    echo -e "${BOLD}${CYAN}Starting services (foreground mode)...${NC}"
    
    # Redis en background
    start_redis
    
    # Dashboard en background
    start_dashboard
    
    # OOB en background
    start_oob || true
    
    show_status
    
    echo ""
    echo -e "${GREEN}${BOLD}Starting Proxy in foreground (Ctrl+C to stop)...${NC}"
    echo -e "${CYAN}Burp plugin guide:${NC} http://127.0.0.1:$DASHBOARD_PORT/dashboard#/burpguide"
    echo -e "${CYAN}Next step:${NC} branche le plugin Burp, configure le scope, puis génère du trafic dans Burp."
    echo ""
    
    # Cleanup handler
    cleanup() {
        echo ""
        log "Shutting down..."
        stop_all
        exit 0
    }
    trap cleanup SIGINT SIGTERM
    
    # Proxy en foreground
    mitmdump \
        -s ghost_hunter/core/interceptor/proxy.py \
        -p $PROXY_PORT \
        --set ssl_insecure=true
}

# ==================== Watch Logs ====================

watch_logs() {
    echo -e "${CYAN}${BOLD}Following all logs (Ctrl+C to stop)...${NC}"
    echo ""
    
    if command -v multitail &> /dev/null; then
        multitail "$LOG_DIR"/*.log
    else
        tail -f "$LOG_DIR"/*.log
    fi
}

# ==================== Main ====================

case "${1:-all}" in
    setup)
        exec "$SCRIPT_DIR/hunter_setup.sh"
        ;;
    all|start)
        start_all
        ;;
    fg|foreground)
        start_foreground
        ;;
    stop)
        stop_all
        ;;
    restart)
        stop_all
        sleep 2
        start_all
        ;;
    nuke|force-restart)
        echo -e "${RED}${BOLD}☢️  NUKE MODE - Force restart complet${NC}"
        force_stop_all
        sleep 3
        start_all
        ;;
    kill|force-stop)
        force_stop_all
        ;;
    status)
        activate_venv
        show_status
        ;;
    logs)
        watch_logs
        ;;
    debug)
        echo -e "${YELLOW}${BOLD}🔍 Mode DEBUG - Logs verbeux${NC}"
        echo ""
        echo "=== Processus Ghost-Hunter ==="
        ps aux | grep -E "mitmdump|uvicorn|redis" | grep -v grep || echo "(aucun)"
        echo ""
        echo "=== Ports utilisés ==="
        echo "Port 6379 (Redis):"
        lsof -i :6379 2>/dev/null || echo "  libre"
        echo "Port 1010 (Dashboard):"
        lsof -i :1010 2>/dev/null || echo "  libre"
        echo "Port 8888 (Proxy):"
        lsof -i :8888 2>/dev/null || echo "  libre"
        echo ""
        echo "=== Derniers logs ==="
        echo "--- dashboard.log ---"
        tail -10 "$LOG_DIR/dashboard.log" 2>/dev/null || echo "(vide)"
        echo ""
        echo "--- proxy.log ---"
        tail -10 "$LOG_DIR/proxy.log" 2>/dev/null || echo "(vide)"
        ;;
    redis)
        activate_venv
        start_redis
        ;;
    proxy)
        activate_venv
        start_proxy
        ;;
    dashboard)
        activate_venv
        start_dashboard
        ;;
    oob)
        activate_venv
        start_oob
        ;;
    help|--help|-h)
        print_banner
        echo "Usage: $0 [command]"
        echo ""
        echo -e "${GREEN}Commands:${NC}"
        echo "  setup         First-run interactive setup"
        echo "  all, start    Start all services (background)"
        echo "  fg            Start with proxy in foreground"
        echo "  stop          Stop all services"
        echo "  restart       Restart all services"
        echo ""
        echo -e "${RED}Robust options:${NC}"
        echo "  nuke          ☢️  Force kill tout + restart (si bloqué)"
        echo "  kill          Force stop sans restart"
        echo "  debug         Affiche l'état détaillé (processus, ports, logs)"
        echo ""
        echo -e "${CYAN}Info:${NC}"
        echo "  status        Show services status"
        echo "  logs          Follow all logs"
        echo ""
        echo -e "${YELLOW}Individual services:${NC}"
        echo "  redis         Start Redis only"
        echo "  proxy         Start Proxy only"
        echo "  dashboard     Start Dashboard only"
        echo "  oob           Start OOB Listener only"
        echo ""
        ;;
    *)
        error "Unknown command: $1"
        echo "Use '$0 help' for usage"
        exit 1
        ;;
esac
