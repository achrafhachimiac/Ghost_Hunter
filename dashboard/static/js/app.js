// Ghost Hunter Dashboard - Vue Application

import { api } from '/static/js/api.js';
import { utils } from '/static/js/utils.js';
import * as smartlogs from '/static/js/smartlogs.js';

const { createApp, ref, computed, onMounted, onUnmounted, watch, nextTick } = Vue;

// Valid views for hash routing
const VALID_VIEWS = ['overview', 'services', 'endpoints', 'requests', 'findings', 'security', 'logs', 'smartlogs', 'aitriage', 'pivotagent', 'config', 'burpguide'];

// Get initial view from URL hash
function getViewFromHash() {
    const hash = window.location.hash.replace('#/', '').replace('#', '');
    return VALID_VIEWS.includes(hash) ? hash : 'overview';
}

export function createGhostHunterApp() {
    return createApp({
        setup() {
            // ==================== STATE ====================
            const currentView = ref(getViewFromHash());
            const health = ref({ services: {}, target: '', running_services: 0, total_services: 5 });
            const stats = ref({});
            const requests = ref([]);
            const findings = ref([]);
            const serviceLogs = ref({});
            const scope = ref({ in_scope: [], out_of_scope: [], target: {} });
            const apiKeys = ref({ groq: { api_key: '' }, openrouter: { api_key: '' }, openai: { api_key: '' } });
            const scopeTargetName = ref('');
            const scopeTargetUrl = ref('');
            const scopeNotes = ref('');
            const scopeInText = ref('');
            const scopeOutText = ref('');
            const savingScope = ref(false);
            const savingApiKeys = ref(false);
            const configMessage = ref('');
            
            // Knowledge Base (RAG)
            const kbStatus = ref({
                total_chunks: 0,
                chunks_by_source: {},
                last_sync: {},
                vector_store_healthy: false,
                errors: []
            });

            // Endpoints
            const endpoints = ref([]);
            const endpointsSummary = ref({ total: 0, by_status: {} });
            const selectedEndpoint = ref(null);
            const endpointFilter = ref('');
            const endpointExcludeFilter = ref('');  // Keywords to exclude (comma-separated)
            const endpointStatusFilter = ref('');
            const endpointMethodFilter = ref('');
            const hideOutOfScope = ref(true);
            const hideStaticAssets = ref(true);
            const neverTriagedOnly = ref(false);  // Filter: show only never triaged endpoints
            const endpointSortBy = ref('score');
            const endpointSortDesc = ref(true);
            const triagingEndpoint = ref(null);
            
            // Pagination endpoints
            const endpointsPage = ref(1);
            const endpointsPages = ref(0);
            const endpointsTotal = ref(0);
            const endpointsPerPage = ref(50);
            const endpointsLoading = ref(false);
            const endpointsSilentRefresh = ref(false);  // For background updates without spinner
            
            // Bulk Selection for Endpoints
            const endpointSelectedItems = ref(new Set());  // Set of selected hashes
            const bulkTriagingActive = ref(false);
            const bulkTriageProgress = ref({ current: 0, total: 0, currentItem: null });

            // Security profiles
            const securityProfiles = ref([]);
            const selectedSecurityProfile = ref(null);
            const scanningScope = ref(false);
            const lastScanResult = ref(null);

            // Filters
            const requestFilter = ref('');
            const requestMethodFilter = ref('');
            const findingSeverityFilter = ref('');
            const selectedLogService = ref('all');
            const logLevelFilter = ref('');
            const autoScrollLogs = ref(true);

            // UI state
            const selectedRequest = ref(null);
            const logsContainer = ref(null);

            // Smart Logs (legacy - kept for compatibility)
            const smartLogsData = ref([]);
            const smartLogFilter = ref('all');
            const autoScrollSmartLogs = ref(true);
            const smartLogsContainer = ref(null);
            const totalLogsFiltered = ref(0);
            const copyButtonText = ref('Copy All');

            // Error Logs (new simplified view)
            const errorLogs = ref([]);

            // AI Triage History
            const triageHistory = ref([]);
            const triageFilter = ref('all');
            
            // Bulk Selection for AI Triage
            const triageSelectedItems = ref(new Set());  // Set of selected hashes
            const bulkTestingActive = ref(false);
            const bulkTestProgress = ref({ current: 0, total: 0, currentItem: null });
            const selectAllTriage = ref(false);  // For "select all" checkbox

            // Pivot Agent
            const pivotLogs = ref([]);
            const pivotFindings = ref([]);
            const pivotAgentActive = ref(false);
            const pivotIteration = ref(0);  // Track current iteration for cost awareness
            const selectedPivotLog = ref('');
            const availableLogs = ref([]);
            const pivotConsole = ref(null);
            let pivotPollInterval = null;
            
            // Detailed debug panels
            const httpRequestHistory = ref([]);  // HTTP requests with full details
            const llmResponses = ref([]);        // LLM responses (full, not truncated)
            const showHttpPanel = ref(false);
            const showLlmPanel = ref(false);
            const selectedHttpRequest = ref(null);
            const selectedLlmResponse = ref(null);

            let refreshInterval = null;

            // ==================== COMPUTED ====================
            const totalFindings = computed(() => {
                const sev = stats.value.findings_by_severity || {};
                return (sev.critical || 0) + (sev.high || 0) + (sev.medium || 0) + (sev.low || 0) + (sev.info || 0);
            });

            const healthBadgeClass = computed(() => {
                if (health.value.running_services === health.value.total_services) {
                    return 'bg-green-500/20 text-green-400';
                } else if (health.value.running_services > 0) {
                    return 'bg-yellow-500/20 text-yellow-400';
                }
                return 'bg-red-500/20 text-red-400';
            });

            const allServicesRunning = computed(() => health.value.running_services === health.value.total_services);
            const anyServiceRunning = computed(() => health.value.running_services > 0);

            const filteredRequests = computed(() => {
                return requests.value.filter(req => {
                    if (requestMethodFilter.value && req.method !== requestMethodFilter.value) return false;
                    if (requestFilter.value) {
                        const filter = requestFilter.value.toLowerCase();
                        return req.path.toLowerCase().includes(filter) || req.host.toLowerCase().includes(filter);
                    }
                    return true;
                });
            });

            const filteredEndpoints = computed(() => {
                // Le filtrage et le tri sont faits côté serveur maintenant
                // On applique seulement les filtres locaux (hideOutOfScope, hideStaticAssets, method)
                let result = endpoints.value.filter(ep => {
                    if (hideOutOfScope.value && ep.status === 'out_of_scope') return false;
                    if (hideStaticAssets.value && ep.status === 'static_asset') return false;
                    if (endpointMethodFilter.value && ep.method !== endpointMethodFilter.value) return false;
                    return true;
                });
                return result;
            });
            
            // Pagination controls
            const goToEndpointsPage = async (page) => {
                if (page < 1 || page > endpointsPages.value) return;
                endpointsPage.value = page;
                await fetchEndpoints();
            };
            
            const nextEndpointsPage = async () => {
                if (endpointsPage.value < endpointsPages.value) {
                    await goToEndpointsPage(endpointsPage.value + 1);
                }
            };
            
            const prevEndpointsPage = async () => {
                if (endpointsPage.value > 1) {
                    await goToEndpointsPage(endpointsPage.value - 1);
                }
            };
            
            // Helper for pagination page numbers display
            const getPageNumber = (index) => {
                // Show pages around current page
                const current = endpointsPage.value;
                const total = endpointsPages.value;
                const start = Math.max(1, Math.min(current - 2, total - 4));
                return start + index - 1;
            };
            
            // Debounced search - re-fetch when filter changes
            let searchTimeout = null;
            const onEndpointFilterChange = () => {
                clearTimeout(searchTimeout);
                searchTimeout = setTimeout(async () => {
                    endpointsPage.value = 1;
                    await fetchEndpoints();
                }, 300);
            };
            
            // Debounced exclude filter - re-fetch when filter changes
            let excludeTimeout = null;
            const onEndpointExcludeFilterChange = () => {
                clearTimeout(excludeTimeout);
                excludeTimeout = setTimeout(async () => {
                    endpointsPage.value = 1;
                    await fetchEndpoints();
                }, 300);
            };
            
            const onEndpointStatusFilterChange = async () => {
                endpointsPage.value = 1;
                await fetchEndpoints();
            };
            
            const onNeverTriagedChange = async () => {
                endpointsPage.value = 1;
                await fetchEndpoints();
            };

            const filteredFindings = computed(() => {
                if (!findingSeverityFilter.value) return findings.value;
                return findings.value.filter(f => f.severity === findingSeverityFilter.value);
            });

            const combinedLogs = computed(() => {
                let logs = [];
                if (selectedLogService.value === 'all') {
                    for (const [service, svcLogs] of Object.entries(serviceLogs.value)) {
                        logs.push(...svcLogs.map(l => ({ ...l, service })));
                    }
                } else {
                    logs = (serviceLogs.value[selectedLogService.value] || []).map(l => ({ ...l, service: selectedLogService.value }));
                }
                if (logLevelFilter.value) logs = logs.filter(l => l.level === logLevelFilter.value);
                return logs.sort((a, b) => a.timestamp.localeCompare(b.timestamp));
            });

            // Smart Logs computed
            const smartLogStats = computed(() => smartlogs.calculateStats(smartLogsData.value));
            const smartLogsCount = computed(() => smartLogsData.value.length);
            const filteredSmartLogs = computed(() => {
                if (smartLogFilter.value === 'all') return smartLogsData.value;
                return smartLogsData.value.filter(l => l.category === smartLogFilter.value);
            });

            // AI Triage History computed
            const filteredTriageHistory = computed(() => {
                if (triageFilter.value === 'all') return triageHistory.value;
                if (triageFilter.value === 'interesting') return triageHistory.value.filter(t => t.interesting);
                return triageHistory.value.filter(t => !t.interesting);
            });

            // ==================== METHODS ====================
            const toggleEndpointSort = async (column) => {
                if (endpointSortBy.value === column) {
                    endpointSortDesc.value = !endpointSortDesc.value;
                } else {
                    endpointSortBy.value = column;
                    endpointSortDesc.value = true;
                }
                // Re-fetch avec le nouveau tri
                endpointsPage.value = 1;
                await fetchEndpoints();
            };

            // Data fetching
            const fetchHealth = async () => { health.value = await api.getHealth(); };
            const fetchStats = async () => { stats.value = await api.getStats(); };
            const fetchRequests = async () => { requests.value = await api.getRequests(); };
            const fetchFindings = async () => { findings.value = await api.getFindings(); };
            const fetchScope = async () => {
                scope.value = await api.getScope();
                scopeTargetName.value = scope.value?.target?.name || '';
                scopeTargetUrl.value = scope.value?.target?.program_url || '';
                scopeNotes.value = scope.value?.notes || '';
                scopeInText.value = (scope.value?.in_scope || []).join('\n');
                scopeOutText.value = (scope.value?.out_of_scope || []).join('\n');
            };
            const fetchApiKeys = async () => {
                apiKeys.value = await api.getApiKeys();
            };

            const saveScopeConfig = async () => {
                savingScope.value = true;
                configMessage.value = '';
                try {
                    const payload = {
                        target: {
                            name: scopeTargetName.value.trim(),
                            program_url: scopeTargetUrl.value.trim(),
                        },
                        in_scope: scopeInText.value.split('\n').map(v => v.trim()).filter(Boolean),
                        out_of_scope: scopeOutText.value.split('\n').map(v => v.trim()).filter(Boolean),
                        notes: scopeNotes.value.trim(),
                    };
                    const result = await api.updateScope(payload);
                    if (result?.status === 'ok') {
                        configMessage.value = '✅ Scope saved';
                        await fetchScope();
                    } else {
                        configMessage.value = '❌ Failed to save scope';
                    }
                } catch (e) {
                    configMessage.value = `❌ ${e.message}`;
                } finally {
                    savingScope.value = false;
                }
            };

            const saveApiKeysConfig = async () => {
                savingApiKeys.value = true;
                configMessage.value = '';
                try {
                    const result = await api.updateApiKeys(apiKeys.value);
                    configMessage.value = result?.status === 'ok' ? '✅ API keys saved' : '❌ Failed to save API keys';
                    await fetchApiKeys();
                } catch (e) {
                    configMessage.value = `❌ ${e.message}`;
                } finally {
                    savingApiKeys.value = false;
                }
            };
            
            // Knowledge Base
            const fetchKBStatus = async () => {
                try {
                    const data = await api.getKBStatus();
                    kbStatus.value = data;
                } catch (e) {
                    console.error('Failed to fetch KB status:', e);
                    kbStatus.value = {
                        total_chunks: 0,
                        chunks_by_source: {},
                        last_sync: {},
                        vector_store_healthy: false,
                        errors: [e.message]
                    };
                }
            };
            
            const refreshKBStatus = async () => { await fetchKBStatus(); };
            
            const syncKBSource = async (source) => {
                try {
                    const data = await api.syncKBSource(source);
                    if (data.success) {
                        alert(`✅ Sync ${source}: ${data.chunks_added || data.total_chunks_added || 0} chunks added`);
                    } else {
                        alert(`❌ Sync ${source} failed: ${data.errors?.join(', ') || 'Unknown error'}`);
                    }
                    await fetchKBStatus();
                } catch (e) {
                    alert(`❌ Sync ${source} failed: ${e.message}`);
                }
            };
            
            const kbSourceColor = (source) => {
                const colors = {
                    'nvd': 'text-blue-400',
                    'cve': 'text-blue-400',
                    'hacktricks': 'text-green-400',
                    'nuclei': 'text-yellow-400',
                    'personal': 'text-purple-400'
                };
                return colors[source] || 'text-gray-400';
            };
            
            // Endpoints avec pagination côté serveur
            const fetchEndpoints = async (silent = false) => {
                // Don't show spinner for silent/background refreshes
                if (!silent) endpointsLoading.value = true;
                endpointsSilentRefresh.value = true;
                try {
                    const data = await api.getEndpoints({
                        limit: endpointsPerPage.value,
                        offset: (endpointsPage.value - 1) * endpointsPerPage.value,
                        sortBy: endpointSortBy.value,
                        sortDesc: endpointSortDesc.value,
                        status: endpointStatusFilter.value || null,
                        search: endpointFilter.value || null,
                        exclude: endpointExcludeFilter.value || null,
                        neverTriaged: neverTriagedOnly.value,
                    });
                    endpoints.value = data.endpoints || [];
                    endpointsTotal.value = data.total || 0;
                    endpointsPages.value = data.pages || 0;
                    // Don't update page if it would cause issues
                    if (!silent) endpointsPage.value = data.page || 1;
                } finally {
                    endpointsLoading.value = false;
                    endpointsSilentRefresh.value = false;
                }
            };
            
            const fetchEndpointsSummary = async () => { endpointsSummary.value = await api.getEndpointsSummary(); };
            const fetchSecurityProfiles = async () => { securityProfiles.value = await api.getSecurityProfiles(); };

            const fetchServiceLogs = async (svc) => {
                serviceLogs.value[svc] = await api.getServiceLogs(svc);
            };

            const fetchAllLogs = async () => {
                for (const svc of Object.keys(health.value.services || {})) {
                    await fetchServiceLogs(svc);
                }
            };

            // Full refresh (manual) - shows loading indicators
            const refreshAll = async () => {
                await Promise.all([
                    fetchHealth(),
                    fetchStats(),
                    fetchRequests(),
                    fetchFindings(),
                    fetchAllLogs(),
                    fetchEndpoints(),  // Full refresh with spinner
                    fetchEndpointsSummary(),
                    fetchSecurityProfiles()
                ]);
            };
            
            // Light refresh (auto) - silent, doesn't block UI
            const refreshLight = async () => {
                await Promise.all([
                    fetchHealth(),
                    fetchStats(),
                    fetchRequests(),
                    fetchFindings(),
                    fetchEndpointsSummary()  // Only summary, not full endpoints list
                ]);
            };
            
            // Silent endpoints refresh for background updates
            const refreshEndpointsSilent = async () => {
                await fetchEndpoints(true);  // Silent mode
            };

            const refreshEndpoints = async () => {
                await Promise.all([fetchEndpoints(), fetchEndpointsSummary()]);
            };

            // Service control
            const startAllServices = async () => { await api.startAllServices(); await refreshAll(); };
            const stopAllServices = async () => { await api.stopAllServices(); await refreshAll(); };
            const startService = async (n) => { await api.startService(n); await fetchHealth(); };
            const stopService = async (n) => { await api.stopService(n); await fetchHealth(); };
            const restartService = async (n) => { await api.restartService(n); await fetchHealth(); };

            // Reset ALL data
            const resetAllData = async () => {
                if (!confirm('⚠️ RESET COMPLET\n\nCeci va effacer:\n- Tous les endpoints\n- Toutes les requêtes\n- Tous les findings\n- L\'historique de triage\n- Les logs\n\nContinuer?')) {
                    return;
                }
                try {
                    const result = await api.resetAllData();
                    if (result?.status === 'ok') {
                        alert(`✅ Reset effectué!\n\n- ${result.endpoints_cleared} endpoints effacés\n- ${result.requests_cleared} requêtes effacées\n- ${result.findings_cleared} findings effacés\n- ${result.triage_cleared} triages effacés\n- ${result.security_profiles_cleared || 0} security profiles effacés\n- Redis: ${result.redis_cleared ? '✓' : '✗'}\n- Logs: ${result.logs_cleared ? '✓' : '✗'}`);
                        // Rafraîchir tout
                        triageHistory.value = [];
                        await refreshAll();
                    } else {
                        alert('❌ Erreur lors du reset');
                    }
                } catch (e) {
                    alert(`❌ Erreur: ${e.message}`);
                }
            };

            // Scan scope domains for security profiles
            const scanScopeDomains = async () => {
                if (scanningScope.value) return;
                scanningScope.value = true;
                lastScanResult.value = null;
                try {
                    const result = await fetch('/api/security/scan/scope', { method: 'POST' });
                    const data = await result.json();
                    if (result.ok) {
                        lastScanResult.value = data;
                        // Refresh security profiles to show new data
                        await fetchSecurityProfiles();
                    } else {
                        alert(`❌ Scan failed: ${data.detail || 'Unknown error'}`);
                    }
                } catch (e) {
                    alert(`❌ Scan error: ${e.message}`);
                } finally {
                    scanningScope.value = false;
                }
            };

            const viewServiceLogs = (n) => {
                selectedLogService.value = n;
                currentView.value = 'logs';
            };

            const clearLogs = () => { serviceLogs.value = {}; };

            // Endpoint triage
            const triageEndpoint = async (hash, endpoint) => {
                triagingEndpoint.value = hash;
                try {
                    const result = await api.triageEndpoint(hash);
                    if (result?.status === 'ok') {
                        // Trouver l'endpoint pour avoir les infos
                        const ep = endpoints.value.find(e => e.hash === hash) || {};
                        
                        // Ajouter au début de l'historique
                        triageHistory.value.unshift({
                            timestamp: new Date().toLocaleString(),
                            hash: hash,
                            method: ep.method || 'GET',
                            host: ep.host || '',
                            path: ep.path_template || '',
                            interesting: result.interesting,
                            confidence: result.confidence,
                            reason: result.reason,
                            suggested_vulns: result.suggested_vulns || [],
                            attack_surface_hints: result.attack_surface_hints || [],  // NEW
                            new_status: result.new_status,
                            model: result.model,
                            tokens: result.tokens || 0,
                            tested: false,
                            testResult: null,
                        });
                        
                        // Naviguer vers l'onglet AI Triage
                        currentView.value = 'aitriage';
                    } else {
                        alert(`Triage Error: ${result?.message || result?.detail || 'Unknown error'}`);
                    }
                    await refreshEndpoints();
                } catch (e) {
                    alert(`Triage Failed: ${e.message}`);
                } finally {
                    triagingEndpoint.value = null;
                }
            };

            // ==================== BULK ENDPOINT SELECTION & TRIAGE ====================
            
            // Toggle selection for a single endpoint
            const toggleEndpointSelection = (ep) => {
                const hash = ep.hash;
                const newSet = new Set(endpointSelectedItems.value);
                if (newSet.has(hash)) {
                    newSet.delete(hash);
                } else {
                    newSet.add(hash);
                }
                endpointSelectedItems.value = newSet;
            };
            
            // Check if endpoint is selected
            const isEndpointSelected = (ep) => {
                return endpointSelectedItems.value.has(ep.hash);
            };
            
            // Toggle all endpoints on current page
            const toggleSelectAllEndpoints = () => {
                const selectableEndpoints = filteredEndpoints.value.filter(ep => 
                    ep.status !== 'interesting' && ep.status !== 'triaged' && ep.status !== 'tested'
                );
                const allSelected = selectableEndpoints.every(ep => endpointSelectedItems.value.has(ep.hash));
                
                const newSet = new Set(endpointSelectedItems.value);
                if (allSelected) {
                    // Deselect all on current page
                    selectableEndpoints.forEach(ep => newSet.delete(ep.hash));
                } else {
                    // Select all pending endpoints on current page
                    selectableEndpoints.forEach(ep => newSet.add(ep.hash));
                }
                endpointSelectedItems.value = newSet;
            };
            
            // Count selected endpoints
            const selectedEndpointCount = computed(() => endpointSelectedItems.value.size);
            
            // Check if all selectable endpoints are selected
            const allEndpointsSelected = computed(() => {
                const selectableEndpoints = filteredEndpoints.value.filter(ep => 
                    ep.status !== 'interesting' && ep.status !== 'triaged' && ep.status !== 'tested'
                );
                return selectableEndpoints.length > 0 && selectableEndpoints.every(ep => endpointSelectedItems.value.has(ep.hash));
            });
            
            // Run bulk triage on all selected endpoints
            const runBulkEndpointTriage = async () => {
                const selectedHashes = Array.from(endpointSelectedItems.value);
                if (selectedHashes.length === 0) {
                    alert('Please select at least one endpoint to triage');
                    return;
                }
                
                bulkTriagingActive.value = true;
                bulkTriageProgress.value = { current: 0, total: selectedHashes.length, currentItem: null };
                
                const results = { success: 0, failed: 0, interesting: 0 };
                
                for (let i = 0; i < selectedHashes.length; i++) {
                    if (!bulkTriagingActive.value) break; // Allow cancellation
                    
                    const hash = selectedHashes[i];
                    const ep = endpoints.value.find(e => e.hash === hash);
                    
                    if (!ep) continue;
                    
                    bulkTriageProgress.value = { 
                        current: i + 1, 
                        total: selectedHashes.length, 
                        currentItem: `${ep.method} ${ep.path_template || ''}`.substring(0, 50)
                    };
                    
                    try {
                        const result = await api.triageEndpoint(hash);
                        
                        if (result?.status === 'ok') {
                            // Add to triage history
                            triageHistory.value.unshift({
                                timestamp: new Date().toLocaleString(),
                                hash: hash,
                                method: ep.method || 'GET',
                                host: ep.host || '',
                                path: ep.path_template || '',
                                interesting: result.interesting,
                                confidence: result.confidence,
                                reason: result.reason,
                                suggested_vulns: result.suggested_vulns || [],
                                attack_surface_hints: result.attack_surface_hints || [],  // NEW
                                new_status: result.new_status,
                                model: result.model,
                                tokens: result.tokens || 0,
                                tested: false,
                                testResult: null,
                            });
                            results.success++;
                            if (result.interesting) {
                                results.interesting++;
                            }
                        } else {
                            results.failed++;
                        }
                    } catch (e) {
                        console.error(`Bulk triage failed for ${hash}:`, e);
                        results.failed++;
                    }
                    
                    // Small delay between requests
                    await new Promise(resolve => setTimeout(resolve, 300));
                }
                
                bulkTriagingActive.value = false;
                bulkTriageProgress.value = { current: 0, total: 0, currentItem: null };
                
                // Clear selection after bulk triage
                endpointSelectedItems.value = new Set();
                
                // Refresh endpoints
                await refreshEndpoints();
                
                // Show summary and navigate to triage view
                alert(`Bulk Triage Complete!\n\n✅ Success: ${results.success}\n❌ Failed: ${results.failed}\n⭐ Interesting: ${results.interesting}`);
                
                if (results.interesting > 0) {
                    currentView.value = 'aitriage';
                }
            };
            
            // Cancel bulk triage
            const cancelBulkTriage = () => {
                bulkTriagingActive.value = false;
            };

            // Test an interesting endpoint with the HTTP Runner
            const testTriageItem = async (item, index) => {
                item.testing = true;
                try {
                    const result = await api.testEndpoint(item.hash, {
                        suggested_vulns: item.suggested_vulns,
                        confidence: item.confidence,
                        use_stealth: item.useStealth || false,  // Pass stealth mode flag
                    });
                    
                    if (result?.status === 'ok') {
                        item.tested = true;
                        item.testResult = {
                            payloads_tested: result.payloads_tested,
                            injection_points: result.injection_points,
                            vuln_class: result.vuln_class,
                            findings: result.findings || [],
                            test_details: result.test_details || [],  // Détails des requêtes/réponses
                            new_status: result.new_status,
                            stealth_mode: result.stealth_mode || false,  // Track if stealth was used
                            // Strategist debug info for popup
                            strategy_prompt: result.strategy_prompt || '',
                            strategy_response: result.strategy_response || '',
                            strategy_model: result.strategy_model || '',
                            strategy_tokens: result.strategy_tokens || 0,
                        };
                        
                        // Si des findings ont été découverts, rafraîchir les findings
                        if (result.findings && result.findings.length > 0) {
                            await fetchFindings();
                        }
                        
                        await refreshEndpoints();
                    } else {
                        alert(`Test Error: ${result?.message || result?.detail || 'Unknown error'}`);
                    }
                } catch (e) {
                    alert(`Test Failed: ${e.message}`);
                } finally {
                    item.testing = false;
                }
            };
            
            // Alias for sendToStrategist (same as testTriageItem)
            const sendToStrategist = testTriageItem;

            // ==================== MULTI-ROUND ATTACK ====================
            
            // Start a multi-round adaptive attack
            const startMultiRoundAttack = async (item, index) => {
                item.multiRoundRunning = true;
                item.multiRoundStatus = 'Starting...';
                
                try {
                    // Get vuln class from suggested_vulns
                    const vulnClass = item.suggested_vulns?.[0] || 'IDOR';
                    
                    const result = await fetch(`/api/endpoints/${item.hash}/multi-round`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            vuln_class: vulnClass,
                            max_rounds: 5,
                            payloads_per_round: 5,
                            use_stealth: item.useStealth || false,
                        })
                    }).then(r => r.json());
                    
                    if (result.status === 'started') {
                        item.multiRoundStatus = 'Running...';
                        // Start polling for status
                        pollMultiRoundStatus(item);
                    } else if (result.status === 'already_running') {
                        item.multiRoundStatus = result.message;
                    } else {
                        alert(`Multi-round error: ${result.message || result.detail || 'Unknown error'}`);
                        item.multiRoundRunning = false;
                    }
                } catch (e) {
                    alert(`Multi-round failed: ${e.message}`);
                    item.multiRoundRunning = false;
                }
            };
            
            // Poll for multi-round attack status
            const pollMultiRoundStatus = async (item) => {
                const maxPolls = 120; // 2 minutes max
                let polls = 0;
                
                const poll = async () => {
                    try {
                        const status = await fetch(`/api/endpoints/${item.hash}/multi-round/status`)
                            .then(r => r.json());
                        
                        item.multiRoundStatus = status.message || `Round ${status.current_round}/${status.total_rounds}`;
                        
                        if (status.status === 'completed') {
                            item.multiRoundRunning = false;
                            item.multiRoundResult = status;
                            item.tested = true;
                            
                            // Refresh findings if any were found
                            if (status.findings_count > 0) {
                                await fetchFindings();
                            }
                            return;
                        } else if (status.status === 'error') {
                            item.multiRoundRunning = false;
                            alert(`Multi-round error: ${status.message}`);
                            return;
                        }
                        
                        // Continue polling
                        polls++;
                        if (polls < maxPolls && item.multiRoundRunning) {
                            setTimeout(poll, 1000);
                        } else if (polls >= maxPolls) {
                            item.multiRoundStatus = 'Timeout - check logs';
                        }
                    } catch (e) {
                        console.error('Poll error:', e);
                        polls++;
                        if (polls < maxPolls && item.multiRoundRunning) {
                            setTimeout(poll, 2000);
                        }
                    }
                };
                
                poll();
            };
            
            // View multi-round attack history - downloads a full dump file
            const viewMultiRoundHistory = async (item) => {
                try {
                    // Download the dump file directly
                    const response = await fetch(`/api/multi-round/${item.hash}/dump`);
                    
                    if (!response.ok) {
                        const error = await response.json();
                        throw new Error(error.detail || 'Failed to generate dump');
                    }
                    
                    // Get filename from Content-Disposition header or generate one
                    const disposition = response.headers.get('Content-Disposition');
                    let filename = `attack_dump_${item.hash.substring(0, 8)}.txt`;
                    if (disposition) {
                        const match = disposition.match(/filename="?([^"]+)"?/);
                        if (match) filename = match[1];
                    }
                    
                    // Create blob and download
                    const blob = await response.blob();
                    const url = window.URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = filename;
                    document.body.appendChild(a);
                    a.click();
                    window.URL.revokeObjectURL(url);
                    document.body.removeChild(a);
                    
                    console.log('Downloaded attack dump:', filename);
                } catch (e) {
                    console.error('Failed to download attack history:', e);
                    alert(`Failed to download attack history: ${e.message}`);
                }
            };

            // ==================== BULK TRIAGE SELECTION & TEST ====================
            
            // Toggle selection for a single triage item
            const toggleTriageSelection = (item) => {
                const hash = item.hash;
                const newSet = new Set(triageSelectedItems.value);
                if (newSet.has(hash)) {
                    newSet.delete(hash);
                } else {
                    newSet.add(hash);
                }
                triageSelectedItems.value = newSet;
            };
            
            // Check if item is selected
            const isTriageSelected = (item) => {
                return triageSelectedItems.value.has(item.hash);
            };
            
            // Toggle all items selection (only interesting ones by default)
            const toggleSelectAllTriage = () => {
                const interestingItems = filteredTriageHistory.value.filter(t => t.interesting && !t.tested);
                const allSelected = interestingItems.every(t => triageSelectedItems.value.has(t.hash));
                
                const newSet = new Set(triageSelectedItems.value);
                if (allSelected) {
                    // Deselect all
                    interestingItems.forEach(t => newSet.delete(t.hash));
                } else {
                    // Select all interesting untested items
                    interestingItems.forEach(t => newSet.add(t.hash));
                }
                triageSelectedItems.value = newSet;
            };
            
            // Count selected items
            const selectedTriageCount = computed(() => triageSelectedItems.value.size);
            
            // Check if all interesting untested items are selected
            const allInterestingSelected = computed(() => {
                const interestingItems = filteredTriageHistory.value.filter(t => t.interesting && !t.tested);
                return interestingItems.length > 0 && interestingItems.every(t => triageSelectedItems.value.has(t.hash));
            });
            
            // Run bulk test on all selected items
            const runBulkTriageTest = async () => {
                const selectedHashes = Array.from(triageSelectedItems.value);
                if (selectedHashes.length === 0) {
                    alert('Please select at least one item to test');
                    return;
                }
                
                bulkTestingActive.value = true;
                bulkTestProgress.value = { current: 0, total: selectedHashes.length, currentItem: null };
                
                const results = { success: 0, failed: 0, findings: 0 };
                
                for (let i = 0; i < selectedHashes.length; i++) {
                    const hash = selectedHashes[i];
                    const item = triageHistory.value.find(t => t.hash === hash);
                    
                    if (!item) continue;
                    
                    bulkTestProgress.value = { 
                        current: i + 1, 
                        total: selectedHashes.length, 
                        currentItem: `${item.method} ${item.path}`.substring(0, 60)
                    };
                    
                    try {
                        item.testing = true;
                        const result = await api.testEndpoint(item.hash, {
                            suggested_vulns: item.suggested_vulns,
                            confidence: item.confidence,
                            use_stealth: item.useStealth || false,
                        });
                        
                        if (result?.status === 'ok') {
                            item.tested = true;
                            item.testResult = {
                                payloads_tested: result.payloads_tested,
                                injection_points: result.injection_points,
                                vuln_class: result.vuln_class,
                                findings: result.findings || [],
                                test_details: result.test_details || [],
                                new_status: result.new_status,
                                stealth_mode: result.stealth_mode || false,
                            };
                            results.success++;
                            if (result.findings && result.findings.length > 0) {
                                results.findings += result.findings.length;
                            }
                        } else {
                            results.failed++;
                        }
                    } catch (e) {
                        console.error(`Bulk test failed for ${hash}:`, e);
                        results.failed++;
                    } finally {
                        item.testing = false;
                    }
                    
                    // Small delay between tests to avoid overwhelming the server
                    await new Promise(resolve => setTimeout(resolve, 500));
                }
                
                bulkTestingActive.value = false;
                bulkTestProgress.value = { current: 0, total: 0, currentItem: null };
                
                // Clear selection after bulk test
                triageSelectedItems.value = new Set();
                
                // Refresh data
                await fetchFindings();
                await refreshEndpoints();
                
                // Show summary
                alert(`Bulk Test Complete!\n\n✅ Success: ${results.success}\n❌ Failed: ${results.failed}\n🐛 Findings: ${results.findings}`);
            };
            
            // Cancel bulk test (set flag to stop loop)
            const cancelBulkTest = () => {
                bulkTestingActive.value = false;
            };

            // Clear triage history (persisted)
            const clearTriageHistory = async () => {
                await api.clearTriageHistory();
                triageHistory.value = [];
            };

            // Security profile
            const fetchSecurityProfile = async (domain) => {
                selectedSecurityProfile.value = await api.getSecurityProfile(domain);
            };

            // Smart logs (legacy)
            const processLogsForSmartView = () => {
                const result = smartlogs.processLogs(serviceLogs.value);
                smartLogsData.value = result.logs;
                totalLogsFiltered.value = result.filtered;
            };

            const clearSmartLogs = () => {
                smartLogsData.value = [];
                totalLogsFiltered.value = 0;
            };

            const copySmartLogs = async () => {
                const text = smartlogs.formatLogsForClipboard(filteredSmartLogs.value);
                await utils.copyToClipboard(text);
                copyButtonText.value = '✓ Copied!';
                setTimeout(() => { copyButtonText.value = 'Copy All'; }, 2000);
            };

            // Smart log styling
            const getSmartLogClass = (log) => smartlogs.getLogClass(log.category);
            const getSmartLogIcon = (log) => log.icon || 'fas fa-info-circle';
            const getSmartLogBadgeClass = (log) => smartlogs.getLogBadgeClass(log.category);
            const getSmartLogTextClass = (log) => smartlogs.getLogTextClass(log.category);

            // ==================== ERROR LOGS (Simple Syslog) ====================
            const refreshErrorLogs = async () => {
                const logs = [];
                const services = ['redis', 'proxy', 'dashboard', 'oob', 'pipeline'];
                
                for (const service of services) {
                    try {
                        const data = await api.fetch(`/api/services/${service}/logs?limit=500`);
                        const serviceLogs = data?.logs || [];
                        
                        for (const log of serviceLogs) {
                            const msg = log.message || '';
                            // Filter only errors
                            if (/error|exception|traceback|failed|❌|critical/i.test(msg)) {
                                logs.push({
                                    timestamp: log.timestamp || new Date().toISOString().substr(11, 8),
                                    service: service.toUpperCase(),
                                    level: 'ERROR',
                                    message: msg.replace(/^\[.*?\]\s*/, '').substring(0, 500),
                                });
                            }
                        }
                    } catch (e) {
                        // Ignore fetch errors
                    }
                }
                
                // Sort by timestamp desc
                logs.sort((a, b) => b.timestamp.localeCompare(a.timestamp));
                errorLogs.value = logs.slice(0, 200);  // Keep last 200 errors
            };

            const clearErrorLogs = () => {
                errorLogs.value = [];
            };

            const copyErrorLogs = async () => {
                const text = errorLogs.value
                    .map(l => `${l.timestamp} [${l.service}] ${l.level} ${l.message}`)
                    .join('\n');
                await utils.copyToClipboard(text);
            };
            // ==================== PIVOT AGENT ====================
            const launchPivotAgent = async () => {
                if (!selectedPivotLog.value || pivotAgentActive.value) return;
                try {
                    pivotLogs.value = [];
                    pivotFindings.value = [];
                    pivotIteration.value = 0;  // Reset iteration counter
                    const response = await fetch(`/api/pivot/run/${selectedPivotLog.value}`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({})
                    });
                    if (response.ok) {
                        pivotAgentActive.value = true;
                        startPivotPolling();
                    } else {
                        const err = await response.json();
                        alert('Failed to launch agent: ' + (err.detail || 'Unknown error'));
                    }
                } catch (e) {
                    console.error('Failed to launch pivot agent:', e);
                    alert('Failed to launch agent: ' + e.message);
                }
            };

            const stopPivotAgent = async () => {
                // Send emergency stop to backend
                if (selectedPivotLog.value) {
                    try {
                        const response = await fetch(`/api/pivot/stop/${selectedPivotLog.value}`, {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' }
                        });
                        if (response.ok) {
                            console.log('🛑 Emergency stop signal sent');
                        }
                    } catch (e) {
                        console.error('Failed to send stop signal:', e);
                    }
                }
                
                // Stop local polling
                pivotAgentActive.value = false;
                if (pivotPollInterval) {
                    clearInterval(pivotPollInterval);
                    pivotPollInterval = null;
                }
            };

            const startPivotPolling = () => {
                if (pivotPollInterval) clearInterval(pivotPollInterval);
                pivotPollInterval = setInterval(async () => {
                    await fetchPivotLogs();
                    await checkPivotStatus();
                }, 1000);
            };

            const fetchPivotLogs = async () => {
                if (!selectedPivotLog.value) return;
                try {
                    const response = await fetch(`/api/pivot/logs/${selectedPivotLog.value}`);
                    if (response.ok) {
                        const data = await response.json();
                        // Reverse to show oldest first (chronological order)
                        pivotLogs.value = (data.entries || []).slice().reverse();
                        // Extract findings
                        pivotFindings.value = pivotLogs.value.filter(e => e.type === 'finding');
                        // Extract current iteration from latest log
                        if (pivotLogs.value.length > 0) {
                            const latestIteration = Math.max(...pivotLogs.value.map(e => e.iteration || 0));
                            pivotIteration.value = latestIteration;
                        }
                        
                        // Extract HTTP requests from logs
                        httpRequestHistory.value = (data.http_requests || []).slice().reverse();
                        
                        // Extract LLM responses from logs
                        llmResponses.value = (data.llm_responses || []).slice().reverse();
                        
                        // Auto-scroll to bottom (latest log)
                        if (pivotConsole.value) {
                            nextTick(() => { pivotConsole.value.scrollTop = pivotConsole.value.scrollHeight; });
                        }
                    }
                } catch (e) {
                    console.error('Failed to fetch pivot logs:', e);
                }
            };

            const checkPivotStatus = async () => {
                if (!selectedPivotLog.value) return;
                try {
                    const response = await fetch(`/api/pivot/status/${selectedPivotLog.value}`);
                    if (response.ok) {
                        const data = await response.json();
                        // Update iteration from status
                        if (data.iteration) {
                            pivotIteration.value = data.iteration;
                        }
                        if (!data.is_active && pivotAgentActive.value) {
                            pivotAgentActive.value = false;
                            pivotIteration.value = 0;
                            if (pivotPollInterval) {
                                clearInterval(pivotPollInterval);
                                pivotPollInterval = null;
                            }
                        }
                    }
                } catch (e) {
                    console.error('Failed to check pivot status:', e);
                }
            };

            const clearPivotLogs = () => {
                pivotLogs.value = [];
                pivotFindings.value = [];
                httpRequestHistory.value = [];
                llmResponses.value = [];
            };

            const fetchAvailableLogs = async () => {
                try {
                    // Fetch endpoints (aggregated from proxy) - sorted by score
                    const response = await fetch('/api/endpoints?limit=100&sort_by=score&sort_desc=true');
                    if (response.ok) {
                        const data = await response.json();
                        const endpointsList = data.endpoints || [];
                        
                        // Filter out static assets and low-value endpoints
                        availableLogs.value = endpointsList
                            .filter(ep => {
                                // Skip static assets
                                if (ep.status === 'static_asset') return false;
                                if (ep.status === 'out_of_scope') return false;
                                // Skip paths that look like static files
                                if (ep.path_template?.match(/\.(js|css|png|jpg|gif|svg|ico|woff|woff2|ttf|eot)$/i)) return false;
                                // Prefer endpoints with interesting params or auth
                                return true;
                            })
                            .slice(0, 50)
                            .map(ep => ({
                                id: ep.hash,
                                method: ep.method,
                                path: ep.path_template,
                                host: ep.host,
                                score: ep.heuristic_score || 0,
                                status: ep.status,
                                has_auth: ep.has_auth,
                                params: ep.param_names || [],
                                // For API compatibility with pivot agent
                                url: ep.example_url,
                                example_request_headers: ep.example_headers,
                                cookies: ep.example_cookies,
                                body: ep.example_body,
                                body_json: ep.example_body_json,
                            }));
                        
                        console.log(`[PivotAgent] Loaded ${availableLogs.value.length} endpoints for analysis`);
                    }
                } catch (e) {
                    console.error('Failed to fetch available logs:', e);
                }
            };

            const getPivotLogClass = (entry) => {
                if (entry.type === 'finding') return 'bg-red-900/30';
                if (entry.type === 'error') return 'bg-red-900/20';
                if (entry.level === 'success') return 'bg-green-900/20';
                return '';
            };

            const getPivotNodeClass = (node) => {
                const colors = {
                    'analyzer': 'text-blue-400',
                    'researcher': 'text-cyan-400',
                    'strategist': 'text-purple-400',
                    'executor': 'text-yellow-400',
                    'pivoter': 'text-pink-400',
                    'system': 'text-gray-400'
                };
                return colors[node] || 'text-gray-400';
            };

            const getPivotLevelClass = (level) => {
                const colors = {
                    'error': 'text-red-400',
                    'warning': 'text-yellow-400',
                    'success': 'text-green-400',
                    'info': 'text-gray-300'
                };
                return colors[level] || 'text-gray-300';
            };

            const formatPivotTime = (ts) => {
                if (!ts) return '';
                const d = new Date(ts * 1000);
                return d.toLocaleTimeString();
            };
            // ==================== WATCHERS ====================
            watch(combinedLogs, () => {
                if (autoScrollLogs.value && logsContainer.value) {
                    nextTick(() => { logsContainer.value.scrollTop = logsContainer.value.scrollHeight; });
                }
            });

            watch(serviceLogs, () => { processLogsForSmartView(); }, { deep: true });

            watch(filteredSmartLogs, () => {
                if (autoScrollSmartLogs.value && smartLogsContainer.value) {
                    nextTick(() => { smartLogsContainer.value.scrollTop = smartLogsContainer.value.scrollHeight; });
                }
            });

            // Load error logs when switching to smartlogs view
            watch(currentView, async (newView) => {
                if (newView === 'smartlogs') {
                    await refreshErrorLogs();
                }
                if (newView === 'pivotagent') {
                    await fetchAvailableLogs();
                }
            });

            // ==================== HASH ROUTING ====================
            // Update URL when view changes
            watch(currentView, (newView) => {
                const newHash = `#/${newView}`;
                if (window.location.hash !== newHash) {
                    window.history.pushState(null, '', newHash);
                }
            }, { immediate: true });
            
            // Listen to browser back/forward
            const handleHashChange = () => {
                const viewFromHash = getViewFromHash();
                if (currentView.value !== viewFromHash) {
                    currentView.value = viewFromHash;
                }
            };
            window.addEventListener('hashchange', handleHashChange);
            window.addEventListener('popstate', handleHashChange);

            // ==================== LIFECYCLE ====================
            onMounted(async () => {
                await Promise.all([fetchScope(), fetchApiKeys()]);
                // Charger l'historique des triages persisté
                triageHistory.value = await api.getTriageHistory();
                // Charger les error logs initiaux
                await refreshErrorLogs();
                // Charger le statut de la Knowledge Base
                await fetchKBStatus();
                await refreshAll();
                // Use light refresh for auto-refresh (doesn't block endpoints UI)
                refreshInterval = setInterval(refreshLight, 3000);  // 3s instead of 2s
            });

            onUnmounted(() => {
                if (refreshInterval) clearInterval(refreshInterval);
                if (pivotPollInterval) clearInterval(pivotPollInterval);
                window.removeEventListener('hashchange', handleHashChange);
                window.removeEventListener('popstate', handleHashChange);
            });

            // ==================== RETURN ====================
            
            // Helper to format headers for display
            const formatHeaders = (headers) => {
                if (!headers) return '';
                if (typeof headers === 'string') return headers;
                return Object.entries(headers).map(([k, v]) => `${k}: ${v}`).join('\n');
            };
            
            // Helper to format body for display (prettify JSON if possible)
            const formatBody = (body, bodyJson = null) => {
                if (!body) return '';
                // If we have parsed JSON with actual content, use it for pretty formatting
                // Check that bodyJson is not empty {} or null
                if (bodyJson && typeof bodyJson === 'object' && Object.keys(bodyJson).length > 0) {
                    try {
                        return JSON.stringify(bodyJson, null, 2);
                    } catch (e) {
                        // Fall through to raw body
                    }
                }
                // Try to parse and prettify JSON from raw body
                if (typeof body === 'string') {
                    try {
                        const parsed = JSON.parse(body);
                        return JSON.stringify(parsed, null, 2);
                    } catch (e) {
                        // Not JSON, return as-is (form-urlencoded, etc.)
                        return body;
                    }
                }
                return String(body);
            };
            
            return {
                // State
                currentView, health, stats, requests, findings, serviceLogs, scope,
                apiKeys, scopeTargetName, scopeTargetUrl, scopeNotes, scopeInText, scopeOutText,
                savingScope, savingApiKeys, configMessage,
                // Knowledge Base (RAG)
                kbStatus, refreshKBStatus, syncKBSource, kbSourceColor,
                endpoints, endpointsSummary, selectedEndpoint, endpointFilter,
                endpointExcludeFilter, neverTriagedOnly,  // New filters
                endpointStatusFilter, endpointMethodFilter, hideOutOfScope, hideStaticAssets,
                endpointSortBy, endpointSortDesc, triagingEndpoint,
                // Pagination endpoints
                endpointsPage, endpointsPages, endpointsTotal, endpointsPerPage, 
                endpointsLoading, endpointsSilentRefresh,
                goToEndpointsPage, nextEndpointsPage, prevEndpointsPage, getPageNumber,
                onEndpointFilterChange, onEndpointStatusFilterChange,
                onEndpointExcludeFilterChange, onNeverTriagedChange,  // New callbacks
                // Bulk Endpoint Selection
                endpointSelectedItems, bulkTriagingActive, bulkTriageProgress,
                toggleEndpointSelection, isEndpointSelected, toggleSelectAllEndpoints,
                selectedEndpointCount, allEndpointsSelected, runBulkEndpointTriage, cancelBulkTriage,
                securityProfiles, selectedSecurityProfile, scanningScope, lastScanResult,
                requestFilter, requestMethodFilter, findingSeverityFilter,
                selectedLogService, logLevelFilter, autoScrollLogs,
                selectedRequest, logsContainer,

                // Computed
                totalFindings, healthBadgeClass, allServicesRunning, anyServiceRunning,
                filteredRequests, filteredEndpoints, filteredFindings, combinedLogs,

                // Methods
                toggleEndpointSort, refreshAll, refreshEndpoints,
                startAllServices, stopAllServices, startService, stopService, restartService,
                resetAllData, scanScopeDomains, viewServiceLogs, clearLogs, triageEndpoint, fetchSecurityProfile,
                saveScopeConfig, saveApiKeysConfig,
                testTriageItem, sendToStrategist, startMultiRoundAttack, pollMultiRoundStatus, viewMultiRoundHistory, formatHeaders, formatBody,

                // Utils (bound for templates)
                methodClass: utils.methodClass,
                scoreClass: utils.scoreClass,
                statusIcon: utils.statusIcon,
                statusBgClass: utils.statusBgClass,
                severityColor: utils.severityColor,
                endpointStatusClass: utils.endpointStatusClass,
                formatDate: utils.formatDate,
                formatUptime: utils.formatUptime,
                formatTimeAgo: utils.formatTimeAgo,
                formatTimestamp: utils.formatTimestamp,
                copyToClipboard: utils.copyToClipboard,

                // Smart Logs (legacy)
                smartLogs: smartLogsData,
                smartLogFilter, autoScrollSmartLogs, smartLogsContainer,
                totalLogsFiltered, smartLogStats, smartLogsCount, filteredSmartLogs,
                getSmartLogClass, getSmartLogIcon, getSmartLogBadgeClass, getSmartLogTextClass,
                clearSmartLogs, copySmartLogs, copyButtonText,

                // Error Logs (simple syslog)
                errorLogs, refreshErrorLogs, clearErrorLogs, copyErrorLogs,

                // AI Triage History
                triageHistory, triageFilter, filteredTriageHistory, clearTriageHistory,
                // Bulk Triage Selection
                triageSelectedItems, bulkTestingActive, bulkTestProgress, selectAllTriage,
                toggleTriageSelection, isTriageSelected, toggleSelectAllTriage,
                selectedTriageCount, allInterestingSelected, runBulkTriageTest, cancelBulkTest,

                // Pivot Agent
                pivotLogs, pivotFindings, pivotAgentActive, pivotIteration, selectedPivotLog, availableLogs,
                pivotConsole, launchPivotAgent, stopPivotAgent, clearPivotLogs,
                getPivotLogClass, getPivotNodeClass, getPivotLevelClass, formatPivotTime,
                
                // Debug Panels
                httpRequestHistory, llmResponses, showHttpPanel, showLlmPanel,
                selectedHttpRequest, selectedLlmResponse
            };
        }
    });
}

export default createGhostHunterApp;
