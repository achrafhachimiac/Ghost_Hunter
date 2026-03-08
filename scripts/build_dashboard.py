#!/usr/bin/env python3
"""
Build script pour le dashboard Ghost Hunter.
Concatène les templates des vues dans index.html.

Usage:
    python scripts/build_dashboard.py
    
Rollback:
    cp dashboard/static/index_legacy.html dashboard/static/index.html
"""

import os
from pathlib import Path

DASHBOARD_DIR = Path(__file__).parent.parent / "dashboard" / "static"
VIEWS_DIR = DASHBOARD_DIR / "views"
OUTPUT_FILE = DASHBOARD_DIR / "index.html"
SHELL_FILE = DASHBOARD_DIR / "index_shell.html"

# Ordre des vues (pour le v-if/v-else-if)
VIEWS = [
    "overview",
    "services", 
    "endpoints",
    "requests",
    "findings",
    "logs",
    "smartlogs",
    "security",
    "config",
    "burpguide",
    "aitriage",
    "pivotagent"
]

def load_view(name: str) -> str:
    """Charge un template de vue."""
    view_file = VIEWS_DIR / f"{name}.html"
    if not view_file.exists():
        print(f"⚠️  Vue manquante: {name}")
        return f'<div class="text-red-500">View {name} not found</div>'
    
    content = view_file.read_text()
    # Ajouter le wrapper v-if
    return content

def build_views_section() -> str:
    """Construit la section des vues avec v-if."""
    sections = []
    
    for i, view_name in enumerate(VIEWS):
        content = load_view(view_name)
        
        # Premier = v-if, autres = v-else-if
        directive = "v-if" if i == 0 else "v-else-if"
        
        section = f'''                <!-- {view_name.upper()} VIEW -->
                <div {directive}="currentView === '{view_name}'" class="view-{view_name}">
{content}
                </div>
'''
        sections.append(section)
    
    return "\n".join(sections)

def build_dashboard():
    """Construit le fichier index.html final."""
    
    # Template shell (header, sidebar, modals)
    shell_template = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>👻 Ghost Hunter - Command Center</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://unpkg.com/vue@3/dist/vue.global.js"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css" rel="stylesheet">
    <link rel="stylesheet" href="/static/css/styles.css">
</head>
<body class="bg-gray-950 text-gray-100 min-h-screen">
    <div id="app" v-cloak class="flex h-screen overflow-hidden">
        
        <!-- Sidebar -->
        <aside class="w-64 bg-gray-900 border-r border-gray-800 flex flex-col">
            <!-- Logo -->
            <div class="p-4 border-b border-gray-800">
                <div class="flex items-center space-x-3">
                    <div class="w-10 h-10 bg-gradient-to-br from-purple-500 to-pink-500 rounded-lg flex items-center justify-center">
                        <i class="fas fa-ghost text-xl text-white"></i>
                    </div>
                    <div>
                        <h1 class="font-bold text-lg">Ghost Hunter</h1>
                        <p class="text-xs text-gray-500">Command Center</p>
                    </div>
                </div>
            </div>
            
            <!-- Target Info -->
            <div class="p-4 border-b border-gray-800 bg-gray-800/50">
                <p class="text-xs text-gray-500 uppercase tracking-wider mb-1">Target</p>
                <p class="font-medium text-purple-400 truncate">{{ health.target || 'No target' }}</p>
            </div>
            
            <!-- Navigation -->
            <nav class="flex-1 p-2 space-y-1 overflow-y-auto">
                <div @click="currentView = 'overview'" :class="{'active': currentView === 'overview'}"
                     class="sidebar-item p-3 rounded-lg cursor-pointer flex items-center space-x-3 transition">
                    <i class="fas fa-th-large text-gray-400 w-5"></i>
                    <span>Overview</span>
                </div>
                
                <div @click="currentView = 'services'" :class="{'active': currentView === 'services'}"
                     class="sidebar-item p-3 rounded-lg cursor-pointer flex items-center space-x-3 transition">
                    <i class="fas fa-server text-gray-400 w-5"></i>
                    <span>Services</span>
                    <span :class="healthBadgeClass" class="ml-auto text-xs px-2 py-0.5 rounded-full">
                        {{ health.running_services }}/{{ health.total_services }}
                    </span>
                </div>
                
                <div @click="currentView = 'requests'" :class="{'active': currentView === 'requests'}"
                     class="sidebar-item p-3 rounded-lg cursor-pointer flex items-center space-x-3 transition">
                    <i class="fas fa-exchange-alt text-gray-400 w-5"></i>
                    <span>Requests</span>
                    <span class="ml-auto text-xs text-gray-500">{{ requests.length }}</span>
                </div>
                
                <div @click="currentView = 'endpoints'" :class="{'active': currentView === 'endpoints'}"
                     class="sidebar-item p-3 rounded-lg cursor-pointer flex items-center space-x-3 transition">
                    <i class="fas fa-sitemap text-gray-400 w-5"></i>
                    <span>Endpoints</span>
                    <span class="ml-auto text-xs text-purple-400">{{ endpointsSummary.total || 0 }}</span>
                </div>
                
                <div @click="currentView = 'findings'" :class="{'active': currentView === 'findings'}"
                     class="sidebar-item p-3 rounded-lg cursor-pointer flex items-center space-x-3 transition">
                    <i class="fas fa-bug text-gray-400 w-5"></i>
                    <span>Findings</span>
                    <span v-if="findings.length" class="ml-auto text-xs bg-red-500/20 text-red-400 px-2 py-0.5 rounded-full">
                        {{ findings.length }}
                    </span>
                </div>
                
                <div @click="currentView = 'security'" :class="{'active': currentView === 'security'}"
                     class="sidebar-item p-3 rounded-lg cursor-pointer flex items-center space-x-3 transition">
                    <i class="fas fa-shield-alt text-gray-400 w-5"></i>
                    <span>Security</span>
                    <span v-if="securityProfiles.length" class="ml-auto text-xs bg-yellow-500/20 text-yellow-400 px-2 py-0.5 rounded-full">
                        {{ securityProfiles.length }}
                    </span>
                </div>
                
                <div @click="currentView = 'logs'" :class="{'active': currentView === 'logs'}"
                     class="sidebar-item p-3 rounded-lg cursor-pointer flex items-center space-x-3 transition">
                    <i class="fas fa-terminal text-gray-400 w-5"></i>
                    <span>Logs</span>
                </div>
                
                <div @click="currentView = 'smartlogs'" :class="{'active': currentView === 'smartlogs'}"
                     class="sidebar-item p-3 rounded-lg cursor-pointer flex items-center space-x-3 transition">
                    <i class="fas fa-filter text-gray-400 w-5"></i>
                    <span>Smart Logs</span>
                    <span v-if="smartLogsCount > 0" class="ml-auto text-xs bg-purple-500/20 text-purple-400 px-2 py-0.5 rounded-full">
                        {{ smartLogsCount }}
                    </span>
                </div>
                
                <div @click="currentView = 'aitriage'" :class="{'active': currentView === 'aitriage'}"
                     class="sidebar-item p-3 rounded-lg cursor-pointer flex items-center space-x-3 transition">
                    <i class="fas fa-brain text-gray-400 w-5"></i>
                    <span>AI Triage</span>
                    <span v-if="triageHistory.length" class="ml-auto text-xs bg-blue-500/20 text-blue-400 px-2 py-0.5 rounded-full">
                        {{ triageHistory.length }}
                    </span>
                </div>
                
                <div @click="currentView = 'pivotagent'" :class="{'active': currentView === 'pivotagent'}"
                     class="sidebar-item p-3 rounded-lg cursor-pointer flex items-center space-x-3 transition">
                    <i class="fas fa-robot text-gray-400 w-5"></i>
                    <span>Pivot Agent</span>
                    <span v-if="pivotAgentActive" class="ml-auto w-2 h-2 bg-green-500 rounded-full pulse-dot"></span>
                    <span v-else-if="pivotFindings && pivotFindings.length" class="ml-auto text-xs bg-red-500/20 text-red-400 px-2 py-0.5 rounded-full">
                        {{ pivotFindings.length }}
                    </span>
                </div>
                
                <div @click="currentView = 'config'" :class="{'active': currentView === 'config'}"
                     class="sidebar-item p-3 rounded-lg cursor-pointer flex items-center space-x-3 transition">
                    <i class="fas fa-cog text-gray-400 w-5"></i>
                    <span>Config</span>
                </div>

                <div @click="currentView = 'burpguide'" :class="{'active': currentView === 'burpguide'}"
                     class="sidebar-item p-3 rounded-lg cursor-pointer flex items-center space-x-3 transition">
                    <i class="fab fa-buromobelexperte text-gray-400 w-5"></i>
                    <span>Burp Guide</span>
                </div>
            </nav>
            
            <!-- Quick Actions -->
            <div class="p-4 border-t border-gray-800 space-y-2">
                <button @click="startAllServices" :disabled="allServicesRunning"
                        class="w-full bg-green-600 hover:bg-green-700 disabled:bg-gray-700 disabled:cursor-not-allowed px-4 py-2 rounded-lg font-medium transition flex items-center justify-center space-x-2">
                    <i class="fas fa-play"></i>
                    <span>Start All</span>
                </button>
                <button @click="stopAllServices" :disabled="!anyServiceRunning"
                        class="w-full bg-red-600 hover:bg-red-700 disabled:bg-gray-700 disabled:cursor-not-allowed px-4 py-2 rounded-lg font-medium transition flex items-center justify-center space-x-2">
                    <i class="fas fa-stop"></i>
                    <span>Stop All</span>
                </button>
                <button @click="resetAllData"
                        class="w-full bg-orange-600 hover:bg-orange-700 px-4 py-2 rounded-lg font-medium transition flex items-center justify-center space-x-2 mt-4">
                    <i class="fas fa-trash-alt"></i>
                    <span>Reset All Data</span>
                </button>
            </div>
        </aside>
        
        <!-- Main Content -->
        <main class="flex-1 overflow-hidden flex flex-col">
            <!-- Top Bar -->
            <header class="bg-gray-900 border-b border-gray-800 px-6 py-3 flex items-center justify-between">
                <div class="flex items-center space-x-4">
                    <h2 class="text-xl font-semibold capitalize">{{ currentView }}</h2>
                    <span class="text-gray-500">|</span>
                    <span class="text-sm text-gray-400">
                        <i class="fas fa-clock mr-1"></i>
                        {{ formatUptime(stats.duration_seconds) }}
                    </span>
                </div>
                <div class="flex items-center space-x-4">
                    <div class="flex items-center space-x-2 text-sm">
                        <span class="w-2 h-2 bg-green-500 rounded-full pulse-dot"></span>
                        <span class="text-gray-400">Live</span>
                    </div>
                    <button @click="refreshAll" class="p-2 hover:bg-gray-800 rounded-lg transition">
                        <i class="fas fa-sync-alt text-gray-400"></i>
                    </button>
                </div>
            </header>
            
            <!-- Content Area -->
            <div class="flex-1 overflow-y-auto p-6">
                
<!-- ======================== VIEWS START ======================== -->
{VIEWS_CONTENT}
<!-- ======================== VIEWS END ======================== -->
                
            </div>
        </main>
        
        <!-- Request Detail Modal -->
        <div v-if="selectedRequest" class="fixed inset-0 bg-black/80 flex items-center justify-center z-50" @click.self="selectedRequest = null">
            <div class="bg-gray-900 rounded-xl w-3/4 max-h-[80vh] overflow-hidden">
                <div class="p-4 border-b border-gray-800 flex items-center justify-between">
                    <h3 class="font-semibold">Request Details</h3>
                    <button @click="selectedRequest = null" class="text-gray-400 hover:text-white"><i class="fas fa-times"></i></button>
                </div>
                <div class="p-6 overflow-y-auto max-h-[calc(80vh-60px)]">
                    <pre class="bg-gray-950 p-4 rounded-lg text-sm overflow-x-auto">{{ JSON.stringify(selectedRequest, null, 2) }}</pre>
                </div>
            </div>
        </div>
        
        <!-- Endpoint Detail Modal -->
        <div v-if="selectedEndpoint" class="fixed inset-0 bg-black/50 flex items-center justify-center z-50" @click.self="selectedEndpoint = null">
            <div class="glass rounded-xl p-6 max-w-2xl w-full mx-4 max-h-[80vh] overflow-y-auto">
                <div class="flex items-center justify-between mb-4">
                    <h3 class="text-lg font-semibold">
                        <span :class="methodClass(selectedEndpoint.method)" class="text-sm font-mono px-2 py-0.5 rounded mr-2">{{ selectedEndpoint.method }}</span>
                        Endpoint Details
                    </h3>
                    <button @click="selectedEndpoint = null" class="text-gray-400 hover:text-white"><i class="fas fa-times"></i></button>
                </div>
                <div class="space-y-4">
                    <div>
                        <p class="text-xs text-gray-400 uppercase mb-1">Template</p>
                        <p class="font-mono text-sm bg-gray-800 p-2 rounded">{{ selectedEndpoint.host }}{{ selectedEndpoint.path_template }}</p>
                    </div>
                    <div class="grid grid-cols-2 gap-4">
                        <div>
                            <p class="text-xs text-gray-400 uppercase mb-1">Status</p>
                            <span :class="endpointStatusClass(selectedEndpoint.status)" class="text-sm px-2 py-1 rounded">{{ selectedEndpoint.status }}</span>
                        </div>
                        <div>
                            <p class="text-xs text-gray-400 uppercase mb-1">Score</p>
                            <span :class="scoreClass(selectedEndpoint.heuristic_score)" class="text-xl font-bold">{{ selectedEndpoint.heuristic_score }}</span>
                        </div>
                    </div>
                    <div v-if="selectedEndpoint.param_names && selectedEndpoint.param_names.length">
                        <p class="text-xs text-gray-400 uppercase mb-1">Parameters</p>
                        <div class="flex flex-wrap gap-1">
                            <span v-for="param in selectedEndpoint.param_names" :key="param" class="bg-blue-500/20 text-blue-400 px-2 py-0.5 rounded text-xs">{{ param }}</span>
                        </div>
                    </div>
                    <div v-if="selectedEndpoint.potential_vulns && selectedEndpoint.potential_vulns.length">
                        <p class="text-xs text-gray-400 uppercase mb-1">Potential Vulnerabilities</p>
                        <div class="flex flex-wrap gap-1">
                            <span v-for="vuln in selectedEndpoint.potential_vulns" :key="vuln" class="bg-purple-500/20 text-purple-400 px-2 py-0.5 rounded text-xs">{{ vuln }}</span>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
    </div>
    
    <script type="module">
        import { createGhostHunterApp } from '/static/js/app.js';
        createGhostHunterApp().mount('#app');
    </script>
</body>
</html>
'''
    
    # Construire les vues
    views_content = build_views_section()
    
    # Assembler le fichier final
    final_html = shell_template.replace("{VIEWS_CONTENT}", views_content)
    
    # Écrire le fichier
    OUTPUT_FILE.write_text(final_html)
    
    # Stats
    line_count = len(final_html.splitlines())
    print(f"✅ Dashboard construit: {OUTPUT_FILE}")
    print(f"   📄 {line_count} lignes")
    print(f"   📦 {len(VIEWS)} vues incluses")
    print(f"\n🔄 Pour rollback: cp dashboard/static/index_legacy.html dashboard/static/index.html")

if __name__ == "__main__":
    build_dashboard()
