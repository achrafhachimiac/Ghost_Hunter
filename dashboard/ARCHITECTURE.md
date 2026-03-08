# Dashboard Architecture

## Structure des fichiers

```
dashboard/
├── api.py                    # FastAPI backend (port 1010)
└── static/
    ├── index.html            # Application principale (monolithique actuellement)
    ├── index_monolith.html   # Backup de l'original
    ├── css/
    │   └── styles.css        # Styles globaux
    ├── js/
    │   ├── app.js            # Vue 3 application (1216 lignes)
    │   ├── api.js            # API client
    │   ├── utils.js          # Helpers
    │   ├── smartlogs.js      # Smart logs logic
    │   ├── pivot-console.js  # Pivot agent console
    │   ├── store.js          # [NEW] État global partagé
    │   └── viewLoader.js     # [NEW] Chargeur de templates
    └── views/                # [NEW] Templates HTML extraits
        ├── overview.html     # Vue d'ensemble (169 lignes)
        ├── services.html     # Gestion des services (37 lignes)
        ├── endpoints.html    # Liste endpoints (236 lignes)
        ├── requests.html     # Requêtes capturées (42 lignes)
        ├── findings.html     # Vulnérabilités trouvées (33 lignes)
        ├── logs.html         # Logs services (31 lignes)
        ├── smartlogs.html    # Logs erreurs (37 lignes)
        ├── security.html     # Profils sécurité (93 lignes)
        ├── config.html       # Configuration scope (20 lignes)
        ├── aitriage.html     # AI Triage (493 lignes) ⚠️ Plus complexe
        └── pivotagent.html   # Pivot Agent (195 lignes)
```

## État actuel

### Ce qui fonctionne
- L'application monolithique index.html est fonctionnelle
- 11 templates de vues extraits dans `/views/`
- Backup de l'original dans `index_monolith.html`

### Migration future (Vite)

Pour migrer vers une architecture moderne:

1. **Installer Vite**
   ```bash
   npm init vite@latest ghost-hunter-dashboard -- --template vue
   ```

2. **Convertir les templates en SFC**
   ```vue
   <!-- src/views/OverviewView.vue -->
   <template>
     <!-- Contenu de overview.html -->
   </template>
   
   <script setup>
   import { useStore } from '@/stores/main'
   const store = useStore()
   </script>
   ```

3. **Utiliser Pinia pour le state**
   - Migrer `store.js` vers un store Pinia

## Notes techniques

### Vue 3 CDN Limitations
- Pas de SFC (Single File Components)
- Pas de compilation de templates
- Pas de tree-shaking

### Templates extraits
Les fichiers dans `/views/*.html` sont des templates Vue valides qui peuvent être:
- Copiés dans des composants Vue SFC
- Chargés dynamiquement via `viewLoader.js` (expérimental)
- Utilisés comme référence pour reconstruire l'app

### Composants à extraire (priorité)
1. `aitriage.html` - 493 lignes, logique complexe
2. `endpoints.html` - 236 lignes, beaucoup de state
3. `pivotagent.html` - 195 lignes, WebSocket

## API Endpoints utilisés

| Vue | Endpoints |
|-----|-----------|
| overview | `/api/stats`, `/api/health`, `/api/kb/status` |
| services | `/api/health`, `/api/services/{name}/{action}` |
| endpoints | `/api/endpoints`, `/api/endpoints/{hash}/triage` |
| requests | `/api/requests` |
| findings | `/api/findings` |
| logs | `/api/logs/{service}` |
| smartlogs | Combine tous les logs |
| security | `/api/security/profiles`, `/api/security/scan` |
| config | `/api/scope` |
| aitriage | `/api/endpoints/{hash}/triage`, `/api/test-triage` |
| pivotagent | `/api/pivot/launch`, `/api/pivot/status`, WebSocket |

## Prochaines étapes

1. [ ] Tester que les vues extraites sont identiques à l'original
2. [ ] Créer un système de test visuel
3. [ ] Migrer progressivement vers Vite quand le temps le permet
