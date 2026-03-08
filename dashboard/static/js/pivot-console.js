/**
 * Ghost Hunter - Pivot Agent Live Console
 * ========================================
 * WebSocket/Polling client to display AI agent thoughts in real-time
 * 
 * Usage:
 *   Include this script in your dashboard, then:
 *   
 *   const console = new PivotAgentConsole('log-123', document.getElementById('console'));
 *   console.start();
 * 
 * Or with the hacker-style terminal:
 *   
 *   PivotAgentConsole.createTerminal('log-123', document.body);
 */

class PivotAgentConsole {
    constructor(logId, containerElement, options = {}) {
        this.logId = logId;
        this.container = containerElement;
        this.apiBase = options.apiBase || '';
        this.pollInterval = options.pollInterval || 1000;
        this.lastTimestamp = 0;
        this.isRunning = false;
        this.pollTimer = null;
        
        // Styles for different log types
        this.styles = {
            thought: { icon: '🧠', color: '#00d4ff' },
            action: { icon: '⚡', color: '#ff9f00' },
            result: { icon: '📊', color: '#00ff88' },
            finding: { icon: '🎯', color: '#ff0066' },
            error: { icon: '❌', color: '#ff3333' },
            state: { icon: '📋', color: '#888888' },
            progress: { icon: '⏳', color: '#ffcc00' }
        };
        
        this.nodeColors = {
            analyzer: '#00d4ff',
            researcher: '#9d4edd',
            strategist: '#ff6b6b',
            executor: '#ffd93d',
            pivoter: '#6bcb77',
            system: '#888888'
        };
    }
    
    async start() {
        this.isRunning = true;
        this.container.innerHTML = '';
        this.addEntry({
            node: 'system',
            type: 'state',
            message: `🚀 Connecting to agent logs: ${this.logId}`,
            timestamp: Date.now() / 1000
        });
        
        await this.poll();
    }
    
    stop() {
        this.isRunning = false;
        if (this.pollTimer) {
            clearTimeout(this.pollTimer);
        }
    }
    
    async poll() {
        if (!this.isRunning) return;
        
        try {
            const response = await fetch(`${this.apiBase}/api/pivot/logs/${this.logId}?limit=50`);
            const data = await response.json();
            
            if (data.entries && data.entries.length > 0) {
                // Entries are in reverse order (newest first)
                const newEntries = data.entries
                    .filter(e => e.timestamp > this.lastTimestamp)
                    .reverse();
                
                for (const entry of newEntries) {
                    this.addEntry(entry);
                    this.lastTimestamp = Math.max(this.lastTimestamp, entry.timestamp);
                }
            }
        } catch (error) {
            console.error('Poll error:', error);
        }
        
        // Schedule next poll
        this.pollTimer = setTimeout(() => this.poll(), this.pollInterval);
    }
    
    addEntry(entry) {
        const line = document.createElement('div');
        line.className = 'pivot-log-entry';
        
        const style = this.styles[entry.type] || this.styles.thought;
        const nodeColor = this.nodeColors[entry.node] || '#ffffff';
        
        const timestamp = new Date(entry.timestamp * 1000).toLocaleTimeString();
        
        line.innerHTML = `
            <span class="log-time">[${timestamp}]</span>
            <span class="log-node" style="color: ${nodeColor}">[${entry.node}]</span>
            <span class="log-icon">${style.icon}</span>
            <span class="log-message" style="color: ${style.color}">${this.escapeHtml(entry.message)}</span>
        `;
        
        // Add data tooltip if present
        if (entry.data && Object.keys(entry.data).length > 0) {
            line.title = JSON.stringify(entry.data, null, 2);
            line.style.cursor = 'pointer';
            line.onclick = () => this.showDataModal(entry);
        }
        
        this.container.appendChild(line);
        this.container.scrollTop = this.container.scrollHeight;
    }
    
    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
    
    showDataModal(entry) {
        const existing = document.getElementById('pivot-data-modal');
        if (existing) existing.remove();
        
        const modal = document.createElement('div');
        modal.id = 'pivot-data-modal';
        modal.innerHTML = `
            <div class="modal-overlay" onclick="this.parentElement.remove()">
                <div class="modal-content" onclick="event.stopPropagation()">
                    <h3>${entry.node} - ${entry.type}</h3>
                    <pre>${JSON.stringify(entry.data, null, 2)}</pre>
                    <button onclick="this.parentElement.parentElement.parentElement.remove()">Close</button>
                </div>
            </div>
        `;
        document.body.appendChild(modal);
    }
    
    /**
     * Create a hacker-style terminal UI
     */
    static createTerminal(logId, parentElement, options = {}) {
        const terminal = document.createElement('div');
        terminal.className = 'pivot-terminal';
        terminal.innerHTML = `
            <div class="terminal-header">
                <span class="terminal-title">👻 Ghost Hunter - Pivot Agent</span>
                <span class="terminal-status" id="terminal-status-${logId}">● CONNECTING</span>
            </div>
            <div class="terminal-body" id="terminal-body-${logId}"></div>
            <div class="terminal-footer">
                <span>Target: ${logId}</span>
                <span id="terminal-iter-${logId}">Iteration: 0</span>
            </div>
        `;
        
        // Add styles
        if (!document.getElementById('pivot-terminal-styles')) {
            const styles = document.createElement('style');
            styles.id = 'pivot-terminal-styles';
            styles.textContent = `
                .pivot-terminal {
                    background: #0a0a0a;
                    border: 1px solid #333;
                    border-radius: 8px;
                    font-family: 'JetBrains Mono', 'Fira Code', monospace;
                    font-size: 12px;
                    overflow: hidden;
                    box-shadow: 0 4px 20px rgba(0, 255, 136, 0.1);
                }
                
                .terminal-header {
                    background: linear-gradient(90deg, #1a1a2e, #16213e);
                    padding: 10px 15px;
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    border-bottom: 1px solid #333;
                }
                
                .terminal-title {
                    color: #00ff88;
                    font-weight: bold;
                }
                
                .terminal-status {
                    color: #ffcc00;
                    animation: blink 1s infinite;
                }
                
                .terminal-status.active {
                    color: #00ff88;
                }
                
                .terminal-status.error {
                    color: #ff3333;
                }
                
                @keyframes blink {
                    50% { opacity: 0.5; }
                }
                
                .terminal-body {
                    height: 400px;
                    overflow-y: auto;
                    padding: 10px;
                    background: #0d0d0d;
                }
                
                .terminal-body::-webkit-scrollbar {
                    width: 6px;
                }
                
                .terminal-body::-webkit-scrollbar-thumb {
                    background: #333;
                    border-radius: 3px;
                }
                
                .terminal-footer {
                    background: #1a1a2e;
                    padding: 8px 15px;
                    display: flex;
                    justify-content: space-between;
                    color: #666;
                    font-size: 11px;
                    border-top: 1px solid #333;
                }
                
                .pivot-log-entry {
                    margin: 4px 0;
                    line-height: 1.5;
                    word-wrap: break-word;
                }
                
                .log-time {
                    color: #666;
                    margin-right: 8px;
                }
                
                .log-node {
                    font-weight: bold;
                    margin-right: 8px;
                }
                
                .log-icon {
                    margin-right: 6px;
                }
                
                .log-message {
                    /* color set inline */
                }
                
                .pivot-log-entry:hover {
                    background: rgba(255, 255, 255, 0.05);
                }
                
                #pivot-data-modal .modal-overlay {
                    position: fixed;
                    top: 0;
                    left: 0;
                    right: 0;
                    bottom: 0;
                    background: rgba(0, 0, 0, 0.8);
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    z-index: 10000;
                }
                
                #pivot-data-modal .modal-content {
                    background: #1a1a2e;
                    border: 1px solid #333;
                    border-radius: 8px;
                    padding: 20px;
                    max-width: 600px;
                    max-height: 80vh;
                    overflow: auto;
                    color: #fff;
                }
                
                #pivot-data-modal pre {
                    background: #0d0d0d;
                    padding: 15px;
                    border-radius: 4px;
                    overflow-x: auto;
                    color: #00ff88;
                }
                
                #pivot-data-modal button {
                    background: #00ff88;
                    color: #000;
                    border: none;
                    padding: 8px 20px;
                    border-radius: 4px;
                    cursor: pointer;
                    margin-top: 15px;
                }
            `;
            document.head.appendChild(styles);
        }
        
        parentElement.appendChild(terminal);
        
        const bodyElement = document.getElementById(`terminal-body-${logId}`);
        const statusElement = document.getElementById(`terminal-status-${logId}`);
        const iterElement = document.getElementById(`terminal-iter-${logId}`);
        
        const console = new PivotAgentConsole(logId, bodyElement, options);
        
        // Override addEntry to update status
        const originalAddEntry = console.addEntry.bind(console);
        console.addEntry = (entry) => {
            originalAddEntry(entry);
            
            // Update status
            statusElement.textContent = '● ACTIVE';
            statusElement.className = 'terminal-status active';
            
            // Update iteration
            if (entry.iteration !== undefined) {
                iterElement.textContent = `Iteration: ${entry.iteration}`;
            }
            
            // Check for end
            if (entry.message && entry.message.includes('Session complete')) {
                statusElement.textContent = '● COMPLETE';
            }
            if (entry.type === 'error') {
                statusElement.className = 'terminal-status error';
            }
        };
        
        console.start();
        return console;
    }
}

// Export for module usage
if (typeof module !== 'undefined' && module.exports) {
    module.exports = PivotAgentConsole;
}
