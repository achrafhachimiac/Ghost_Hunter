// Ghost Hunter Dashboard - Vue Components Loader
// Charge dynamiquement les templates depuis les fichiers views/*.html

const viewsCache = {};

/**
 * Charge un template de vue depuis /static/views/{name}.html
 * @param {string} viewName - Nom de la vue (ex: 'overview', 'endpoints')
 * @returns {Promise<string>} - Template HTML
 */
export async function loadViewTemplate(viewName) {
    if (viewsCache[viewName]) {
        return viewsCache[viewName];
    }
    
    try {
        const response = await fetch(`/static/views/${viewName}.html`);
        if (!response.ok) {
            throw new Error(`Failed to load view: ${viewName}`);
        }
        const template = await response.text();
        viewsCache[viewName] = template;
        return template;
    } catch (error) {
        console.error(`[ViewLoader] Error loading ${viewName}:`, error);
        return `<div class="text-red-500 p-4">Error loading view: ${viewName}</div>`;
    }
}

/**
 * Précharge toutes les vues au démarrage
 */
export async function preloadAllViews() {
    const viewNames = [
        'overview',
        'services', 
        'endpoints',
        'requests',
        'findings',
        'logs',
        'smartlogs',
        'security',
        'config',
        'aitriage',
        'pivotagent'
    ];
    
    console.log('[ViewLoader] Preloading all views...');
    const startTime = Date.now();
    
    await Promise.all(viewNames.map(name => loadViewTemplate(name)));
    
    console.log(`[ViewLoader] All views loaded in ${Date.now() - startTime}ms`);
    return viewsCache;
}

/**
 * Retourne un objet de composants Vue pour chaque vue
 * Compatible avec Vue 3 CDN (options API)
 */
export function createViewComponents() {
    return {
        'overview-view': {
            template: viewsCache['overview'] || '<div>Loading...</div>',
            inject: ['appState', 'appMethods']
        },
        'services-view': {
            template: viewsCache['services'] || '<div>Loading...</div>',
            inject: ['appState', 'appMethods']
        },
        'endpoints-view': {
            template: viewsCache['endpoints'] || '<div>Loading...</div>',
            inject: ['appState', 'appMethods']
        },
        'requests-view': {
            template: viewsCache['requests'] || '<div>Loading...</div>',
            inject: ['appState', 'appMethods']
        },
        'findings-view': {
            template: viewsCache['findings'] || '<div>Loading...</div>',
            inject: ['appState', 'appMethods']
        },
        'logs-view': {
            template: viewsCache['logs'] || '<div>Loading...</div>',
            inject: ['appState', 'appMethods']
        },
        'smartlogs-view': {
            template: viewsCache['smartlogs'] || '<div>Loading...</div>',
            inject: ['appState', 'appMethods']
        },
        'security-view': {
            template: viewsCache['security'] || '<div>Loading...</div>',
            inject: ['appState', 'appMethods']
        },
        'config-view': {
            template: viewsCache['config'] || '<div>Loading...</div>',
            inject: ['appState', 'appMethods']
        },
        'aitriage-view': {
            template: viewsCache['aitriage'] || '<div>Loading...</div>',
            inject: ['appState', 'appMethods']
        },
        'pivotagent-view': {
            template: viewsCache['pivotagent'] || '<div>Loading...</div>',
            inject: ['appState', 'appMethods']
        }
    };
}

export { viewsCache };
