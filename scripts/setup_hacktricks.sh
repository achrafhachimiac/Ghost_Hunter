#!/bin/bash
# =============================================================================
# Ghost-Hunter - Setup HackTricks Knowledge Base
# =============================================================================
# Clone HackTricks avec sparse-checkout pour économiser l'espace.
# Seulement pentesting-web/ est cloné (~30-50MB au lieu de ~500MB+)
#
# Usage:
#   ./scripts/setup_hacktricks.sh
#   ./scripts/setup_hacktricks.sh --ingest  # Clone + ingestion
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
SOURCES_DIR="$PROJECT_ROOT/knowledge/sources"
HACKTRICKS_DIR="$SOURCES_DIR/hacktricks"
HACKTRICKS_URL="https://github.com/carlospolop/hacktricks.git"

# Couleurs
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}  👻 Ghost-Hunter - HackTricks Setup${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

# Créer le dossier sources si nécessaire
mkdir -p "$SOURCES_DIR"

# Vérifier si déjà cloné
if [ -d "$HACKTRICKS_DIR/.git" ]; then
    echo -e "${YELLOW}📁 HackTricks déjà présent, mise à jour...${NC}"
    cd "$HACKTRICKS_DIR"
    git pull --depth 1 || {
        echo -e "${YELLOW}⚠️  Pull échoué, tentative de reset...${NC}"
        git fetch --depth 1
        git reset --hard origin/master
    }
else
    echo -e "${GREEN}📥 Clonage de HackTricks (sparse checkout)...${NC}"
    
    # Clone sparse
    git clone \
        --depth 1 \
        --filter=blob:none \
        --sparse \
        "$HACKTRICKS_URL" \
        "$HACKTRICKS_DIR"
    
    cd "$HACKTRICKS_DIR"
    
    # Configurer sparse-checkout pour pentesting-web seulement
    echo -e "${GREEN}🎯 Configuration sparse-checkout (pentesting-web/)...${NC}"
    git sparse-checkout set pentesting-web
fi

# Afficher les stats
echo ""
echo -e "${GREEN}📊 Statistiques:${NC}"
REPO_SIZE=$(du -sh "$HACKTRICKS_DIR" | cut -f1)
FILE_COUNT=$(find "$HACKTRICKS_DIR/pentesting-web" -name "*.md" 2>/dev/null | wc -l)
echo "   - Taille du repo: $REPO_SIZE"
echo "   - Fichiers .md: $FILE_COUNT"

# Option --ingest
if [ "$1" == "--ingest" ]; then
    echo ""
    echo -e "${GREEN}🔄 Lancement de l'ingestion...${NC}"
    cd "$PROJECT_ROOT"
    python -c "
from ghost_hunter.core.rag.ingestors.hacktricks import ingest_hacktricks
stats = ingest_hacktricks()
print(f'✅ Ingestion terminée: {stats.chunks_added} chunks ajoutés en {stats.duration_ms:.0f}ms')
if stats.errors:
    print(f'⚠️  Erreurs: {stats.errors}')
"
fi

echo ""
echo -e "${GREEN}✅ Setup HackTricks terminé!${NC}"
echo ""
echo "Pour ingérer dans le vector store:"
echo -e "  ${YELLOW}python -c \"from ghost_hunter.core.rag.ingestors.hacktricks import ingest_hacktricks; ingest_hacktricks()\"${NC}"
echo ""
echo "Ou relancer ce script avec --ingest:"
echo -e "  ${YELLOW}./scripts/setup_hacktricks.sh --ingest${NC}"
