// Ghost Hunter Dashboard - Smart Logs Module

// Patterns to EXCLUDE (noise)
export const noisePatterns = [
    /GET \/api\/(stats|requests|findings|endpoints|services|security|config)/i,
    /client connect$/i,
    /client disconnect$/i,
    /error establishing server connection: client disconnected/i,
    /stream reset by client/i,
    /HTTP\/1\.1" (200|304) OK/i,
    /HTTP\/2\.0 (200|304)/i,
    /INFO: 127\.0\.0\.1:\d+ -/i,
    /RDB (age|memory usage|produced)/i,
    /DB (loaded|saved)/i,
    /Loading RDB/i,
    /Ready to accept connections/i,
    /Server initialized/i,
    /Redis is starting/i,
    /Configuration loaded/i,
    /monotonic clock/i,
    /Running mode=standalone/i,
    /Increased maximum number of open files/i,
    /Done loading RDB/i,
    /User requested shutdown/i,
    /Saving the final RDB snapshot/i,
    /Removing the pid file/i,
    /Redis is now ready to exit/i,
    /WARNING Memory overcommit/i,
    /\.well-known\/appspecific/i,
    /webpack\/js/i,
    /webpack\/\d+/i,
    /\.svg\s+HTTP/i,
    /\.png\s+HTTP/i,
    /\.jpg\s+HTTP/i,
    /\.css\s+HTTP/i,
    /\.woff/i,
    /favicon\.ico/i,
    /Redis version=\d+/i,
    /just started$/i,
    /DedupEngine: \d+ endpoints chargés depuis Redis/i,
    /Clé API OpenRouter chargée/i,
    /Heuristics Engine initialisé/i,
    /Déduplication mémoire activée/i,
    /OOB callbacks managed internally/i,
    /ScopeFilter:/i,
];

// Patterns to HIGHLIGHT (important) - ORDER MATTERS, first match wins
export const importantPatterns = [
    { pattern: /🛡️.*Detected (waf|cdn|anti_bot|rate_limit)/i, category: 'security', icon: 'fas fa-shield-alt' },
    { pattern: /⭐.*\[\d+\].*-.*\[/i, category: 'discovery', icon: 'fas fa-star' },
    { pattern: /🎯 INTÉRESSANT/i, category: 'ai', icon: 'fas fa-brain' },
    { pattern: /🔥 FINDING/i, category: 'findings', icon: 'fas fa-bug' },
    { pattern: /CRITICAL|HIGH|MEDIUM vulnerability/i, category: 'findings', icon: 'fas fa-exclamation-triangle' },
    { pattern: /POST https:\/\/openrouter\.ai/i, category: 'ai', icon: 'fas fa-robot' },
    { pattern: /Knowledge Base activée/i, category: 'system', icon: 'fas fa-book' },
    { pattern: /Nuclei Scanner activé/i, category: 'system', icon: 'fas fa-microscope' },
    { pattern: /🧠 AI Triage/i, category: 'ai', icon: 'fas fa-brain' },
    { pattern: /ERROR|ERREUR/i, category: 'error', icon: 'fas fa-times-circle' },
    { pattern: /DedupEngine: Redis connecté/i, category: 'system', icon: 'fas fa-database' },
    { pattern: /🔥 Ghost-Hunter Pipeline initialisé/i, category: 'system', icon: 'fas fa-rocket' },
    { pattern: /POST|PUT|DELETE|PATCH.*\/api\/(admin|user|account|auth|payment)/i, category: 'discovery', icon: 'fas fa-key' },
];

// Process raw logs and extract smart logs
export function processLogs(serviceLogs) {
    const allLogs = [];
    let filtered = 0;

    for (const [service, svcLogs] of Object.entries(serviceLogs)) {
        for (const log of svcLogs) {
            const msg = log.message || '';

            // Check if noise
            const isNoise = noisePatterns.some(p => p.test(msg));
            if (isNoise) {
                filtered++;
                continue;
            }

            // Find category
            let category = 'info';
            let icon = 'fas fa-info-circle';
            let details = null;

            for (const imp of importantPatterns) {
                if (imp.pattern.test(msg)) {
                    category = imp.category;
                    icon = imp.icon;
                    break;
                }
            }

            // Extract extra details from certain log types
            if (msg.includes('⭐')) {
                const match = msg.match(/\[(\d+)\]\s+(\w+)\s+([^\s-]+)/);
                if (match) {
                    details = `Score: ${match[1]} | Method: ${match[2]} | Endpoint: ${match[3]}`;
                }
            } else if (msg.includes('Detected')) {
                const match = msg.match(/Detected (\w+):\s+([^\s(]+)\s*\((\d+)%\)/);
                if (match) {
                    details = `Type: ${match[1]} | Provider: ${match[2]} | Confidence: ${match[3]}%`;
                }
            }

            allLogs.push({
                service,
                timestamp: log.timestamp,
                level: log.level,
                message: msg,
                category,
                icon,
                details
            });
        }
    }

    return {
        logs: allLogs.sort((a, b) => a.timestamp.localeCompare(b.timestamp)),
        filtered
    };
}

// Get log category CSS class
export function getLogClass(category) {
    return {
        'discovery': 'border-green-500 bg-green-500/5',
        'security': 'border-yellow-500 bg-yellow-500/5',
        'ai': 'border-blue-500 bg-blue-500/5',
        'findings': 'border-red-500 bg-red-500/5',
        'error': 'border-red-600 bg-red-600/10',
        'system': 'border-purple-500 bg-purple-500/5',
        'info': 'border-gray-600 bg-gray-600/5',
    }[category] || 'border-gray-600';
}

// Get log badge class
export function getLogBadgeClass(category) {
    return {
        'discovery': 'bg-green-500/20 text-green-400',
        'security': 'bg-yellow-500/20 text-yellow-400',
        'ai': 'bg-blue-500/20 text-blue-400',
        'findings': 'bg-red-500/20 text-red-400',
        'error': 'bg-red-600/30 text-red-300',
        'system': 'bg-purple-500/20 text-purple-400',
        'info': 'bg-gray-500/20 text-gray-400',
    }[category] || 'bg-gray-500/20 text-gray-400';
}

// Get log text class
export function getLogTextClass(category) {
    return {
        'discovery': 'text-green-300',
        'security': 'text-yellow-300',
        'ai': 'text-blue-300',
        'findings': 'text-red-300',
        'error': 'text-red-400',
        'system': 'text-purple-300',
        'info': 'text-gray-300',
    }[category] || 'text-gray-300';
}

// Calculate log stats by category
export function calculateStats(logs) {
    const stats = { discovery: 0, security: 0, ai: 0, findings: 0, error: 0, system: 0, info: 0 };
    for (const log of logs) {
        if (stats[log.category] !== undefined) {
            stats[log.category]++;
        }
    }
    return stats;
}

// Format logs for clipboard
export function formatLogsForClipboard(logs) {
    return logs.map(log => {
        let line = `[${log.timestamp}][${log.service}][${log.category.toUpperCase()}] ${log.message}`;
        if (log.details) line += `\n    → ${log.details}`;
        return line;
    }).join('\n');
}

export default {
    noisePatterns,
    importantPatterns,
    processLogs,
    getLogClass,
    getLogBadgeClass,
    getLogTextClass,
    calculateStats,
    formatLogsForClipboard
};
