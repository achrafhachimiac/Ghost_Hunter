/**
 * Ghost-Hunter Dashboard - Global Store
 * =====================================
 * État réactif partagé entre toutes les vues.
 * Utilise Vue 3 reactive() pour la réactivité.
 */

const { reactive, ref, computed } = Vue;

// ═══════════════════════════════════════════════════════════════
// STORE GLOBAL
// ═══════════════════════════════════════════════════════════════

export const store = reactive({
    // ─────────────────────────────────────────────────────────────
    // CORE - Health & Stats
    // ─────────────────────────────────────────────────────────────
    health: { 
        services: {}, 
        target: '', 
        running_services: 0, 
        total_services: 5 
    },
    stats: {},
    scope: { 
        in_scope: [], 
        out_of_scope: [], 
        target: {} 
    },
    
    // Knowledge Base
    kbStatus: {
        available: false,
        total_chunks: 0,
        chunks_by_source: {},
        last_sync: {},
        sync_in_progress: null
    },
    
    // ─────────────────────────────────────────────────────────────
    // DATA - Endpoints
    // ─────────────────────────────────────────────────────────────
    endpoints: [],
    endpointsSummary: { total: 0, by_status: {} },
    endpointsPage: 1,
    endpointsPages: 0,
    endpointsTotal: 0,
    endpointsPerPage: 50,
    endpointsLoading: false,
    endpointsSilentRefresh: false,
    endpointSortBy: 'score',
    endpointSortDesc: true,
    
    // Endpoint Filters
    endpointFilter: '',
    endpointExcludeFilter: '',
    endpointStatusFilter: '',
    endpointMethodFilter: '',
    hideOutOfScope: true,
    hideStaticAssets: true,
    neverTriagedOnly: false,
    
    // Endpoint Selection (for bulk operations)
    endpointSelectedItems: new Set(),
    bulkTriagingActive: false,
    bulkTriageProgress: { current: 0, total: 0, currentItem: null },
    
    // ─────────────────────────────────────────────────────────────
    // DATA - Requests
    // ─────────────────────────────────────────────────────────────
    requests: [],
    requestFilter: '',
    requestMethodFilter: '',
    
    // ─────────────────────────────────────────────────────────────
    // DATA - Findings
    // ─────────────────────────────────────────────────────────────
    findings: [],
    findingSeverityFilter: '',
    
    // ─────────────────────────────────────────────────────────────
    // DATA - AI Triage
    // ─────────────────────────────────────────────────────────────
    triageHistory: [],
    triageFilter: 'all',
    triageSelectedItems: new Set(),
    bulkTestingActive: false,
    bulkTestProgress: { current: 0, total: 0, currentItem: null },
    selectAllTriage: false,
    
    // ─────────────────────────────────────────────────────────────
    // DATA - Security Profiles
    // ─────────────────────────────────────────────────────────────
    securityProfiles: [],
    scanningScope: false,
    lastScanResult: null,
    
    // ─────────────────────────────────────────────────────────────
    // DATA - Logs
    // ─────────────────────────────────────────────────────────────
    serviceLogs: {},
    selectedLogService: 'all',
    logLevelFilter: '',
    autoScrollLogs: true,
    
    // Smart Logs
    smartLogsData: [],
    smartLogFilter: 'all',
    autoScrollSmartLogs: true,
    totalLogsFiltered: 0,
    copyButtonText: 'Copy All',
    
    // Error Logs
    errorLogs: [],
    
    // ─────────────────────────────────────────────────────────────
    // DATA - Pivot Agent
    // ─────────────────────────────────────────────────────────────
    pivotLogs: [],
    pivotFindings: [],
    pivotAgentActive: false,
    pivotIteration: 0,
    selectedPivotLog: '',
    availableLogs: [],
    httpRequestHistory: [],
    llmResponses: [],
    showHttpPanel: false,
    showLlmPanel: true,
    
    // ─────────────────────────────────────────────────────────────
    // UI STATE
    // ─────────────────────────────────────────────────────────────
    currentView: 'overview',
    triagingEndpoint: null,  // Hash of endpoint being triaged
    
    // ─────────────────────────────────────────────────────────────
    // MODALS
    // ─────────────────────────────────────────────────────────────
    selectedRequest: null,
    selectedEndpoint: null,
    selectedSecurityProfile: null,
    selectedHttpRequest: null,
    selectedLlmResponse: null,
});

// ═══════════════════════════════════════════════════════════════
// COMPUTED PROPERTIES (Getters)
// ═══════════════════════════════════════════════════════════════

export const getters = {
    // Total findings count
    totalFindings: computed(() => {
        const byCount = store.stats?.findings_by_severity || {};
        return Object.values(byCount).reduce((sum, c) => sum + c, 0);
    }),
    
    // Health badge class
    healthBadgeClass: computed(() => {
        const h = store.health;
        if (h.running_services === h.total_services) return 'bg-green-500';
        if (h.running_services > 0) return 'bg-yellow-500';
        return 'bg-red-500';
    }),
    
    // All services running
    allServicesRunning: computed(() => 
        store.health.running_services === store.health.total_services
    ),
    
    // Any service running
    anyServiceRunning: computed(() => 
        store.health.running_services > 0
    ),
    
    // Filtered requests
    filteredRequests: computed(() => {
        return store.requests.filter(r => {
            if (store.requestFilter && !r.url?.toLowerCase().includes(store.requestFilter.toLowerCase())) return false;
            if (store.requestMethodFilter && r.method !== store.requestMethodFilter) return false;
            return true;
        });
    }),
    
    // Filtered endpoints (basic filter - full logic in composable)
    filteredEndpoints: computed(() => {
        return store.endpoints; // Full filtering in useEndpoints composable
    }),
    
    // Filtered findings
    filteredFindings: computed(() => {
        if (!store.findingSeverityFilter) return store.findings;
        return store.findings.filter(f => f.severity === store.findingSeverityFilter);
    }),
    
    // Combined logs from all services
    combinedLogs: computed(() => {
        const logs = [];
        for (const [service, entries] of Object.entries(store.serviceLogs)) {
            if (store.selectedLogService !== 'all' && store.selectedLogService !== service) continue;
            for (const entry of entries || []) {
                logs.push({ ...entry, service });
            }
        }
        return logs.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp)).slice(0, 200);
    }),
    
    // Filtered triage history
    filteredTriageHistory: computed(() => {
        if (store.triageFilter === 'all') return store.triageHistory;
        if (store.triageFilter === 'interesting') return store.triageHistory.filter(t => t.interesting);
        return store.triageHistory.filter(t => !t.interesting);
    }),
    
    // Selected endpoint count
    selectedEndpointCount: computed(() => store.endpointSelectedItems.size),
    
    // Selected triage count
    selectedTriageCount: computed(() => store.triageSelectedItems.size),
    
    // All interesting selected
    allInterestingSelected: computed(() => {
        const interesting = store.triageHistory.filter(t => t.interesting && !t.tested);
        return interesting.length > 0 && interesting.every(t => store.triageSelectedItems.has(t.hash));
    }),
    
    // All endpoints selected (for current page)
    allEndpointsSelected: computed(() => {
        const selectable = store.endpoints.filter(ep => 
            ep.status !== 'interesting' && ep.status !== 'triaged' && ep.status !== 'tested'
        );
        return selectable.length > 0 && selectable.every(ep => store.endpointSelectedItems.has(ep.hash));
    }),
    
    // Smart log stats
    smartLogStats: computed(() => {
        const stats = { ai: 0, http: 0, finding: 0, error: 0, pivot: 0 };
        for (const log of store.smartLogsData) {
            if (stats[log.category] !== undefined) stats[log.category]++;
        }
        return stats;
    }),
    
    // Smart logs count
    smartLogsCount: computed(() => store.smartLogsData.length),
    
    // Filtered smart logs
    filteredSmartLogs: computed(() => {
        if (store.smartLogFilter === 'all') return store.smartLogsData;
        return store.smartLogsData.filter(log => log.category === store.smartLogFilter);
    }),
};

// ═══════════════════════════════════════════════════════════════
// ACTIONS (Mutations)
// ═══════════════════════════════════════════════════════════════

export const actions = {
    // Set current view
    setView(view) {
        store.currentView = view;
    },
    
    // Reset endpoint selection
    resetEndpointSelection() {
        store.endpointSelectedItems = new Set();
    },
    
    // Reset triage selection
    resetTriageSelection() {
        store.triageSelectedItems = new Set();
    },
    
    // Toggle endpoint selection
    toggleEndpointSelection(hash) {
        const newSet = new Set(store.endpointSelectedItems);
        if (newSet.has(hash)) {
            newSet.delete(hash);
        } else {
            newSet.add(hash);
        }
        store.endpointSelectedItems = newSet;
    },
    
    // Toggle triage selection
    toggleTriageSelection(hash) {
        const newSet = new Set(store.triageSelectedItems);
        if (newSet.has(hash)) {
            newSet.delete(hash);
        } else {
            newSet.add(hash);
        }
        store.triageSelectedItems = newSet;
    },
    
    // Add triage to history
    addTriageToHistory(triage) {
        store.triageHistory.unshift(triage);
        // Keep max 100
        if (store.triageHistory.length > 100) {
            store.triageHistory = store.triageHistory.slice(0, 100);
        }
    },
    
    // Update triage in history
    updateTriageInHistory(hash, updates) {
        const idx = store.triageHistory.findIndex(t => t.hash === hash);
        if (idx !== -1) {
            store.triageHistory[idx] = { ...store.triageHistory[idx], ...updates };
        }
    },
    
    // Clear triage history
    clearTriageHistory() {
        store.triageHistory = [];
    },
    
    // Clear pivot logs
    clearPivotLogs() {
        store.pivotLogs = [];
        store.pivotFindings = [];
        store.httpRequestHistory = [];
        store.llmResponses = [];
    },
    
    // Open modal
    openModal(modalName, data) {
        store[modalName] = data;
    },
    
    // Close modal
    closeModal(modalName) {
        store[modalName] = null;
    },
};

// Export default
export default { store, getters, actions };
