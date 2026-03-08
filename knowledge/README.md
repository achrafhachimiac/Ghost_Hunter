# 📚 Ghost-Hunter Knowledge Base

Ce dossier contient les ressources externes utilisées par Ghost-Hunter pour enrichir l'analyse IA et les tests de sécurité.

## 📁 Structure

```
knowledge/
├── hacktricks/          # HackTricks - Bible du pentester
├── payloads/            # PayloadsAllTheThings - Payloads par vuln
├── wordlists/           # SecLists + Assetnote - Wordlists
├── nuclei-templates/    # Templates Nuclei officiels
├── cheatsheets/         # Bug Bounty cheatsheets
└── patterns/            # Patterns business logic
```

## 🚀 Installation

```bash
# Installer toutes les ressources
./setup_knowledge.sh

# Ou individuellement
./setup_knowledge.sh hacktricks
./setup_knowledge.sh payloads
./setup_knowledge.sh wordlists
./setup_knowledge.sh nuclei
```

## 📊 Usage

Les ressources sont chargées automatiquement par le module `intelligence/`:

```python
from ghost_hunter.core.intelligence import KnowledgeLoader

kb = KnowledgeLoader()

# Obtenir du contexte pour une vuln
context = kb.get_vuln_context("IDOR")
# Retourne: techniques HackTricks + payloads + cheatsheets

# Obtenir des payloads
payloads = kb.get_payloads("sqli", limit=50)

# Obtenir des wordlists
wordlist = kb.get_wordlist("api-endpoints")
```

## 📦 Ressources

| Ressource | Taille | Mise à jour |
|-----------|--------|-------------|
| HackTricks | ~500MB | Mensuelle |
| PayloadsAllTheThings | ~50MB | Mensuelle |
| SecLists | ~1GB | Mensuelle |
| Nuclei Templates | ~100MB | Hebdomadaire |
