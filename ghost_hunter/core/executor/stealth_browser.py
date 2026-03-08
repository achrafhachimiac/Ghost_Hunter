"""
Stealth Browser - Bypass anti-bot protections (Friendly Captcha, Cloudflare, etc.)

Uses Puppeteer with stealth plugin to execute requests that would otherwise be blocked.
This module provides a headless browser that mimics real user behavior.

Usage:
    from ghost_hunter.core.executor.stealth_browser import StealthBrowser
    
    async with StealthBrowser() as browser:
        result = await browser.execute_request(
            method="POST",
            url="https://example.com/api/endpoint",
            headers={"content-type": "application/json"},
            body='{"key": "value"}'
        )
"""

import asyncio
import json
import logging
import subprocess
import tempfile
import os
from pathlib import Path
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, field
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class StealthResponse:
    """Response from stealth browser request."""
    success: bool = False
    status_code: int = 0
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    cookies: Dict[str, str] = field(default_factory=dict)
    error: Optional[str] = None
    execution_time_ms: int = 0
    captcha_solved: bool = False
    

# Node.js script for puppeteer-extra with stealth
PUPPETEER_STEALTH_SCRIPT = '''
const puppeteer = require('puppeteer-extra');
const StealthPlugin = require('puppeteer-extra-plugin-stealth');

// Use stealth plugin
puppeteer.use(StealthPlugin());

const config = JSON.parse(process.argv[2]);

(async () => {
    let browser;
    const result = {
        success: false,
        status_code: 0,
        headers: {},
        body: '',
        cookies: {},
        error: null,
        captcha_solved: false
    };
    
    try {
        // Launch browser with stealth settings
        browser = await puppeteer.launch({
            headless: config.headless !== false ? 'new' : false,
            args: [
                '--no-sandbox',
                '--disable-setuid-sandbox',
                '--disable-blink-features=AutomationControlled',
                '--disable-infobars',
                '--window-size=1920,1080',
                '--start-maximized',
                '--disable-dev-shm-usage',
                '--disable-accelerated-2d-canvas',
                '--disable-gpu',
                '--lang=fr-FR,fr,en-US,en'
            ],
            ignoreHTTPSErrors: true
        });
        
        const page = await browser.newPage();
        
        // Set viewport to look like real browser
        await page.setViewport({ width: 1920, height: 1080 });
        
        // First navigate to the target origin to establish context
        const urlObj = new URL(config.url);
        const originUrl = urlObj.origin;
        
        console.error('[STEALTH] Navigating to origin:', originUrl);
        await page.goto(originUrl, {
            waitUntil: 'domcontentloaded',
            timeout: config.timeout || 30000
        });
        
        // Wait a bit for any anti-bot scripts to settle
        await new Promise(r => setTimeout(r, 1000));
        
        // Set cookies if provided
        if (config.cookies && Object.keys(config.cookies).length > 0) {
            const cookieList = [];
            for (const [name, value] of Object.entries(config.cookies)) {
                cookieList.push({
                    name,
                    value,
                    domain: urlObj.hostname,
                    path: '/',
                    secure: urlObj.protocol === 'https:'
                });
            }
            await page.setCookie(...cookieList);
        }
        
        // Check for Friendly Captcha on the page
        let hasCaptcha = await page.evaluate(() => {
            return document.querySelector('.frc-captcha') !== null ||
                   document.querySelector('[data-sitekey]') !== null ||
                   document.body.innerHTML.includes('friendly-challenge') ||
                   document.body.innerHTML.includes('frc-captcha');
        });
        
        if (hasCaptcha) {
            console.error('[STEALTH] Friendly Captcha detected on page, waiting...');
            // Wait for captcha to auto-solve (stealth plugin helps)
            await new Promise(r => setTimeout(r, 3000));
            result.captcha_solved = true;
        }
        
        // Now execute the actual API request using fetch within page context
        console.error('[STEALTH] Executing fetch request to:', config.url);
        const fetchResult = await page.evaluate(async (cfg) => {
            try {
                const headers = cfg.headers || {};
                if (cfg.content_type) {
                    headers['Content-Type'] = cfg.content_type;
                }
                
                const fetchOptions = {
                    method: cfg.method || 'GET',
                    headers: headers,
                    credentials: 'include'
                };
                
                if (cfg.body && ['POST', 'PUT', 'PATCH'].includes(cfg.method.toUpperCase())) {
                    fetchOptions.body = cfg.body;
                }
                
                const resp = await fetch(cfg.url, fetchOptions);
                const text = await resp.text();
                const respHeaders = {};
                resp.headers.forEach((v, k) => respHeaders[k] = v);
                
                return {
                    status: resp.status,
                    headers: respHeaders,
                    body: text,
                    error: null
                };
            } catch (e) {
                return { status: 0, headers: {}, body: '', error: e.message };
            }
        }, config);
        
        if (fetchResult.error) {
            throw new Error(fetchResult.error);
        }
        
        result.status_code = fetchResult.status;
        result.headers = fetchResult.headers;
        result.body = fetchResult.body;
        
        // Get final cookies
        const cookies = await page.cookies();
        for (const cookie of cookies) {
            result.cookies[cookie.name] = cookie.value;
        }
        
        result.success = true;
        console.error('[STEALTH] Request completed with status:', result.status_code);
        
    } catch (error) {
        result.error = error.message;
        console.error('[STEALTH] Error:', error.message);
    } finally {
        if (browser) {
            await browser.close();
        }
    }
    
    // Output result as JSON
    console.log(JSON.stringify(result));
})();
'''


class StealthBrowser:
    """
    Headless browser with stealth capabilities for bypassing anti-bot protections.
    
    Uses puppeteer-extra with stealth plugin to:
    - Bypass Friendly Captcha detection
    - Evade Cloudflare bot detection
    - Mimic real browser fingerprints
    - Handle JavaScript-required pages
    """
    
    def __init__(
        self,
        headless: bool = True,
        timeout: int = 30000,
        captcha_timeout: int = 120000,  # 2 minutes for captcha solve
        node_path: str = "node",
    ):
        self.headless = headless
        self.timeout = timeout
        self.captcha_timeout = captcha_timeout
        self.node_path = node_path
        self._script_path: Optional[Path] = None
        self._check_dependencies()
    
    def _check_dependencies(self):
        """Check if Node.js and required packages are installed."""
        try:
            result = subprocess.run(
                [self.node_path, "-v"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode != 0:
                raise RuntimeError("Node.js not found")
            logger.debug(f"Node.js version: {result.stdout.strip()}")
        except Exception as e:
            logger.warning(f"Node.js check failed: {e}")
    
    @property
    def is_available(self) -> bool:
        """Check if stealth browser is available."""
        try:
            # Check node
            result = subprocess.run(
                [self.node_path, "-e", "require('puppeteer-extra'); require('puppeteer-extra-plugin-stealth');"],
                capture_output=True,
                text=True,
                timeout=10
            )
            return result.returncode == 0
        except:
            return False
    
    async def __aenter__(self):
        """Async context manager entry."""
        # Create temporary script file
        self._script_path = Path(tempfile.mktemp(suffix=".js"))
        self._script_path.write_text(PUPPETEER_STEALTH_SCRIPT)
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self._script_path and self._script_path.exists():
            self._script_path.unlink()
    
    async def execute_request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        body: Optional[str] = None,
        content_type: Optional[str] = None,
    ) -> StealthResponse:
        """
        Execute HTTP request using stealth browser.
        
        Args:
            method: HTTP method (GET, POST, etc.)
            url: Target URL
            headers: Optional headers dict
            cookies: Optional cookies dict
            body: Optional request body (for POST/PUT/PATCH)
            content_type: Content-Type header
            
        Returns:
            StealthResponse with result
        """
        start_time = datetime.now()
        
        config = {
            "method": method,
            "url": url,
            "headers": headers or {},
            "cookies": cookies or {},
            "body": body,
            "content_type": content_type or "application/json",
            "headless": self.headless,
            "timeout": self.timeout,
            "captcha_timeout": self.captcha_timeout,
        }
        
        try:
            # Create script if not in context manager
            script_path = self._script_path
            cleanup_script = False
            
            # Find project root where node_modules is located
            project_root = Path(__file__).parent.parent.parent.parent
            node_modules_path = project_root / "node_modules"
            
            if not node_modules_path.exists():
                # Try current working directory
                node_modules_path = Path.cwd() / "node_modules"
            
            if not script_path:
                # Create script in project root so it can find node_modules
                script_path = project_root / f"_stealth_temp_{os.getpid()}.js"
                script_path.write_text(PUPPETEER_STEALTH_SCRIPT)
                cleanup_script = True
            
            try:
                # Run puppeteer script from project root
                process = await asyncio.create_subprocess_exec(
                    self.node_path,
                    str(script_path),
                    json.dumps(config),
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    cwd=str(project_root),  # Run from project root
                )
                
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=self.timeout / 1000 + 60  # Extra time for browser startup
                )
                
                if stderr:
                    logger.debug(f"Puppeteer stderr: {stderr.decode()}")
                
                # Parse JSON output (last line)
                output = stdout.decode().strip()
                lines = output.split('\n')
                json_line = lines[-1] if lines else '{}'
                
                result_data = json.loads(json_line)
                
                response = StealthResponse(
                    success=result_data.get("success", False),
                    status_code=result_data.get("status_code", 0),
                    headers=result_data.get("headers", {}),
                    body=result_data.get("body", ""),
                    cookies=result_data.get("cookies", {}),
                    error=result_data.get("error"),
                    captcha_solved=result_data.get("captcha_solved", False),
                )
                
            finally:
                if cleanup_script and script_path.exists():
                    script_path.unlink()
                    
        except asyncio.TimeoutError:
            response = StealthResponse(
                success=False,
                error="Timeout waiting for browser response"
            )
        except json.JSONDecodeError as e:
            response = StealthResponse(
                success=False,
                error=f"Failed to parse browser response: {e}"
            )
        except Exception as e:
            response = StealthResponse(
                success=False,
                error=str(e)
            )
        
        response.execution_time_ms = int((datetime.now() - start_time).total_seconds() * 1000)
        return response


# Singleton for reuse
_stealth_browser: Optional[StealthBrowser] = None


def get_stealth_browser() -> StealthBrowser:
    """Get singleton stealth browser instance."""
    global _stealth_browser
    if _stealth_browser is None:
        _stealth_browser = StealthBrowser()
    return _stealth_browser


async def install_stealth_dependencies():
    """Install required npm packages for stealth browser."""
    packages = ["puppeteer", "puppeteer-extra", "puppeteer-extra-plugin-stealth"]
    
    # Check if already installed
    browser = get_stealth_browser()
    if browser.is_available:
        logger.info("Stealth browser dependencies already installed")
        return True
    
    logger.info("Installing stealth browser dependencies...")
    
    try:
        process = await asyncio.create_subprocess_exec(
            "npm", "install", "-g", *packages,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await process.communicate()
        
        if process.returncode != 0:
            logger.error(f"npm install failed: {stderr.decode()}")
            return False
        
        logger.info("Stealth browser dependencies installed successfully")
        return True
        
    except Exception as e:
        logger.error(f"Failed to install dependencies: {e}")
        return False
