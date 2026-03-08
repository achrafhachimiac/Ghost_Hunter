# 🎯 Pivot Agent - Implementation Todolist

## Overview
Agent de pentest autonome basé sur LangGraph pour pivoter sur des vulnérabilités logiques.
Utilise Ghost-Hunter comme "système d'exploitation" via son API.

---

## ✅ Implementation Status: COMPLETE

## Phase 1: Structure & Configuration
- [x] 1.1 Créer la structure de dossiers `pivot_agent/`
- [x] 1.2 Créer `requirements.txt` (langgraph, langchain, httpx, pydantic)
- [x] 1.3 Créer `config.py` avec les settings (API URL, model, etc.)
- [x] 1.4 Définir `state.py` avec `AgentState` TypedDict

## Phase 2: Tools (Outils pour l'agent)
- [x] 2.1 `tools/gh_api_client.py` - Wrapper API Ghost-Hunter
  - [x] `get_logs()` - Récupère l'historique
  - [x] `get_findings()` - Récupère les vulns
  - [x] `run_request()` - Exécute via HTTP Runner
  - [x] `get_endpoints()` - Liste les endpoints
- [x] 2.2 `tools/pattern_extractor.py` - Extraction de patterns
  - [x] `extract_uuids()` - UUIDs v4
  - [x] `extract_jwts()` - Tokens JWT
  - [x] `extract_numeric_ids()` - IDs numériques
  - [x] `extract_signed_ids()` - IDs signés Rails
  - [x] `extract_all()` - Combine tout
- [x] 2.3 `tools/diff_checker.py` - Comparaison de réponses
  - [x] `diff_json()` - Diff structurel JSON
  - [x] `detect_data_leak()` - Détecte fuites de données
  - [x] `detect_privilege_change()` - Détecte changement de privilèges

## Phase 3: Nodes (Composants du workflow)
- [x] 3.1 `nodes/analyzer.py` - Analyse initiale
  - [x] Analyse le finding/log suspect
  - [x] Identifie le type de vuln potentielle
  - [x] Extrait les paramètres injectables
- [x] 3.2 `nodes/researcher.py` - Recherche contextuelle
  - [x] Recherche requêtes liées dans les logs
  - [x] Identifie patterns d'IDs utilisés
  - [x] Construit le contexte utilisateur
- [x] 3.3 `nodes/strategist.py` - Planification tactique
  - [x] Génère plan d'attaque basé sur l'analyse
  - [x] Priorise les tests (IDOR, Mass Assignment, etc.)
  - [x] Définit les payloads à tester
- [x] 3.4 `nodes/executor.py` - Exécution des tests
  - [x] Exécute les requêtes via Ghost-Hunter API
  - [x] Capture les réponses
  - [x] Log les résultats
- [x] 3.5 `nodes/pivoter.py` - Pivot sur nouvelles données
  - [x] Extrait nouvelles données des réponses
  - [x] Identifie nouvelles pistes d'attaque
  - [x] Décide si continuer ou arrêter

## Phase 4: Graph & Workflow
- [x] 4.1 `graph.py` - Définition du workflow LangGraph
  - [x] Définir les edges (transitions)
  - [x] Définir les conditions de routage
  - [x] Compiler le graph
- [x] 4.2 Implémenter le cycle: Analyze → Research → Strategize → Execute → Pivot → (loop)

## Phase 5: Main & CLI
- [x] 5.1 `main.py` - Point d'entrée
  - [x] Parser les arguments (finding_id, target_lead)
  - [x] Initialiser l'agent
  - [x] Lancer le workflow
  - [x] Afficher les résultats
- [ ] 5.2 Mode interactif (optionnel)

## Phase 6: Tests & Documentation
- [ ] 6.1 Tester sur un finding réel
- [x] 6.2 README.md (this file serves as documentation)

---

## 🚀 Usage

```bash
# Activate virtual environment
source venv/bin/activate

# Set your Anthropic API key
export ANTHROPIC_API_KEY="your-key-here"

# Start from a Ghost-Hunter endpoint
python -m pivot_agent --endpoint abc123

# Target a specific URL
python -m pivot_agent --url https://api.example.com/users/1

# Verbose mode with output file
python -m pivot_agent --endpoint abc123 -v -o results.json

# Limit iterations
python -m pivot_agent --url https://api.example.com/users/1 --max-iter 5
```

---

## Architecture Finale

```
pivot_agent/
├── __init__.py
├── main.py              # Point d'entrée CLI
├── config.py            # Configuration
├── state.py             # AgentState TypedDict
├── graph.py             # Workflow LangGraph
├── tools/
│   ├── __init__.py
│   ├── gh_api_client.py # API Ghost-Hunter
│   ├── pattern_extractor.py
│   └── diff_checker.py
├── nodes/
│   ├── __init__.py
│   ├── analyzer.py
│   ├── researcher.py
│   ├── strategist.py
│   ├── executor.py
│   └── pivoter.py
├── prompts/
│   └── system_prompts.py
├── requirements.txt
└── README.md
```

---

## Dépendances Clés

```
langgraph>=0.0.40
langchain>=0.1.0
langchain-anthropic>=0.1.0
httpx>=0.25.0
pydantic>=2.0.0
rich>=13.0.0  # Pour les logs colorés
```
