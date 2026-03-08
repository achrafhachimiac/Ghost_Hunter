// Ghost Hunter Dashboard - Utility Functions

export const utils = {
    // Method badge class
    methodClass(m) {
        return {
            'GET': 'bg-green-500/20 text-green-400',
            'POST': 'bg-blue-500/20 text-blue-400',
            'PUT': 'bg-yellow-500/20 text-yellow-400',
            'DELETE': 'bg-red-500/20 text-red-400',
            'PATCH': 'bg-purple-500/20 text-purple-400'
        }[m] || 'bg-gray-500/20 text-gray-400';
    },

    // Score color class
    scoreClass(s) {
        if (s >= 70) return 'text-red-400';
        if (s >= 50) return 'text-orange-400';
        if (s >= 30) return 'text-yellow-400';
        return 'text-gray-400';
    },

    // Status icon
    statusIcon(s) {
        return {
            'running': 'fas fa-check-circle',
            'stopped': 'fas fa-stop-circle',
            'error': 'fas fa-exclamation-circle',
            'starting': 'fas fa-spinner fa-spin'
        }[s] || 'fas fa-question-circle';
    },

    // Status background class
    statusBgClass(s) {
        return {
            'running': 'bg-green-500',
            'stopped': 'bg-gray-500',
            'error': 'bg-red-500',
            'starting': 'bg-yellow-500'
        }[s] || 'bg-gray-500';
    },

    // Severity color
    severityColor(s) {
        return {
            'critical': '#dc2626',
            'high': '#ea580c',
            'medium': '#ca8a04',
            'low': '#16a34a',
            'info': '#2563eb'
        }[s] || '#6b7280';
    },

    // Endpoint status class
    endpointStatusClass(status) {
        return {
            'pending': 'bg-gray-500/20 text-gray-400',
            'deduplicated': 'bg-yellow-500/20 text-yellow-400',
            'out_of_scope': 'bg-red-500/20 text-red-400',
            'static_asset': 'bg-gray-500/20 text-gray-500',
            'low_score': 'bg-gray-500/20 text-gray-400',
            'triaged': 'bg-blue-500/20 text-blue-400',
            'interesting': 'bg-green-500/20 text-green-400',
            'tested': 'bg-purple-500/20 text-purple-400',
        }[status] || 'bg-gray-500/20 text-gray-400';
    },

    // Format timestamp to locale string
    formatDate(t) {
        return t ? new Date(t * 1000).toLocaleString() : '';
    },
    
    // Format timestamp to human-readable "time ago" string
    formatTimeAgo(timestamp) {
        if (!timestamp) return 'Never';
        const now = Date.now() / 1000;  // Current time in seconds
        const diff = now - timestamp;
        
        if (diff < 60) return 'Just now';
        if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
        if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
        if (diff < 604800) return `${Math.floor(diff / 86400)}d ago`;
        return new Date(timestamp * 1000).toLocaleDateString();
    },
    
    // Format timestamp to full readable string
    formatTimestamp(timestamp) {
        if (!timestamp) return 'Never';
        return new Date(timestamp * 1000).toLocaleString();
    },

    // Format uptime in human readable form
    formatUptime(s) {
        if (!s) return '0s';
        const h = Math.floor(s / 3600);
        const m = Math.floor((s % 3600) / 60);
        const sec = Math.floor(s % 60);
        if (h > 0) return `${h}h ${m}m ${sec}s`;
        if (m > 0) return `${m}m ${sec}s`;
        return `${sec}s`;
    },

    // Copy text to clipboard
    async copyToClipboard(text) {
        try {
            await navigator.clipboard.writeText(text);
            return true;
        } catch (err) {
            // Fallback for older browsers
            const textarea = document.createElement('textarea');
            textarea.value = text;
            document.body.appendChild(textarea);
            textarea.select();
            document.execCommand('copy');
            document.body.removeChild(textarea);
            return true;
        }
    }
};

export default utils;
