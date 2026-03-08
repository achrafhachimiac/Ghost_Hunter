// Ghost Hunter Dashboard - API Client

export const api = {
    // Generic fetch wrapper
    async fetch(url, options = {}) {
        try {
            const response = await fetch(url, options);
            return await response.json();
        } catch (e) {
            console.error(`API Error [${url}]:`, e);
            return null;
        }
    },

    // Health & Stats
    async getHealth() {
        return await this.fetch('/api/services/health') || { services: {}, target: '', running_services: 0, total_services: 5 };
    },

    async getStats() {
        return await this.fetch('/api/stats') || {};
    },

    async getScope() {
        return await this.fetch('/api/config/scope') || { in_scope: [], out_of_scope: [], target: {} };
    },

    async updateScope(scope) {
        return await this.fetch('/api/config/scope', {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(scope),
        });
    },

    async getApiKeys() {
        return await this.fetch('/api/config/api-keys') || { groq: {}, openrouter: {}, openai: {} };
    },

    async updateApiKeys(apiKeys) {
        return await this.fetch('/api/config/api-keys', {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(apiKeys),
        });
    },

    // Requests
    async getRequests(limit = 100) {
        return await this.fetch(`/api/requests?limit=${limit}`) || [];
    },

    // Findings
    async getFindings(limit = 50) {
        return await this.fetch(`/api/findings?limit=${limit}`) || [];
    },

    // Endpoints - avec pagination côté serveur
    async getEndpoints(options = {}) {
        const {
            limit = 50,
            offset = 0,
            sortBy = 'score',
            sortDesc = true,
            status = null,
            search = null,
            exclude = null,
            neverTriaged = false
        } = options;
        
        let url = `/api/endpoints?limit=${limit}&offset=${offset}&sort_by=${sortBy}&sort_desc=${sortDesc}`;
        if (status) url += `&status=${encodeURIComponent(status)}`;
        if (search) url += `&search=${encodeURIComponent(search)}`;
        if (exclude) url += `&exclude=${encodeURIComponent(exclude)}`;
        if (neverTriaged) url += `&never_triaged=true`;
        
        return await this.fetch(url) || { endpoints: [], total: 0, page: 1, pages: 0 };
    },

    async getEndpointsSummary() {
        const data = await this.fetch('/api/endpoints/summary');
        return data?.summary || { total: 0, by_status: {} };
    },

    async triageEndpoint(hash) {
        return await this.fetch(`/api/endpoints/${hash}/triage`, { method: 'POST' });
    },

    async testEndpoint(hash, body = {}) {
        return await this.fetch(`/api/endpoints/${hash}/test`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
        });
    },

    // Triage History
    async getTriageHistory() {
        const data = await this.fetch('/api/triage/history');
        const history = data?.history || [];
        // Mapper snake_case vers camelCase pour le frontend
        return history.map(item => ({
            ...item,
            testResult: item.test_result || null,  // Mapper test_result -> testResult
        }));
    },

    async clearTriageHistory() {
        return await this.fetch('/api/triage/history', { method: 'DELETE' });
    },

    // Security Profiles
    async getSecurityProfiles() {
        const data = await this.fetch('/api/security');
        return data?.profiles || [];
    },

    async getSecurityProfile(domain) {
        return await this.fetch(`/api/security/${encodeURIComponent(domain)}`);
    },

    // Service Logs
    async getServiceLogs(service, limit = 100) {
        return await this.fetch(`/api/services/${service}/logs?limit=${limit}`) || [];
    },

    // Service Control
    async startService(name) {
        return await this.fetch(`/api/services/${name}/start`, { method: 'POST' });
    },

    async stopService(name) {
        return await this.fetch(`/api/services/${name}/stop`, { method: 'POST' });
    },

    async restartService(name) {
        return await this.fetch(`/api/services/${name}/restart`, { method: 'POST' });
    },

    async startAllServices() {
        return await this.fetch('/api/services/start-all', { method: 'POST' });
    },

    async stopAllServices() {
        return await this.fetch('/api/services/stop-all', { method: 'POST' });
    },

    // Reset all data
    async resetAllData() {
        return await this.fetch('/api/reset', { method: 'POST' });
    },
    
    // Knowledge Base (RAG)
    async getKBStatus() {
        return await this.fetch('/api/kb/status') || {
            total_chunks: 0,
            chunks_by_source: {},
            last_sync: {},
            vector_store_healthy: false,
            errors: []
        };
    },
    
    async syncKBSource(source, force = false) {
        return await this.fetch(`/api/kb/sync?source=${encodeURIComponent(source)}&force=${force}`, { method: 'POST' });
    },
    
    async searchKB(query, limit = 10) {
        return await this.fetch(`/api/kb/search?q=${encodeURIComponent(query)}&limit=${limit}`);
    },
    
    async addKBReport(path) {
        return await this.fetch(`/api/kb/add-report?path=${encodeURIComponent(path)}`, { method: 'POST' });
    },
    
    async rebuildKB() {
        return await this.fetch('/api/kb/rebuild', { method: 'POST' });
    }
};

export default api;
