# -*- coding: utf-8 -*-
"""
Ghost-Hunter Burp Suite Extension
=================================

Extension pour Burp Suite Community Edition qui capture le traffic
et l'envoie a Ghost-Hunter pour analyse AI automatique.

Installation:
1. Telecharger Jython standalone: https://www.jython.org/download
2. Burp -> Extender -> Options -> Python Environment -> Select Jython JAR
3. Burp -> Extender -> Extensions -> Add -> Extension Type: Python -> Select this file

Usage:
1. Configurer le scope dans Burp (Target -> Scope)
2. Naviguer normalement - les requetes in-scope sont capturees
3. Clic-droit sur une requete -> "Send to Ghost-Hunter" pour analyse manuelle
4. Voir l'onglet "Ghost-Hunter" pour les statistiques
"""

from burp import IBurpExtender, IHttpListener, IContextMenuFactory, ITab
from burp import IExtensionStateListener
from javax.swing import (
    JPanel, JButton, JLabel, JTextField, JCheckBox, 
    JTextArea, JScrollPane, BoxLayout, BorderFactory,
    SwingConstants, JOptionPane
)
from javax.swing.border import EmptyBorder
from java.awt import BorderLayout, GridLayout, FlowLayout, Font, Color, Dimension
import json
import threading
import time

# Python 2/Jython compatible HTTP
try:
    from urllib2 import Request, urlopen, URLError
    from urllib import urlencode
except ImportError:
    from urllib.request import Request, urlopen
    from urllib.error import URLError
    from urllib.parse import urlencode


class BurpExtender(IBurpExtender, IHttpListener, IContextMenuFactory, ITab, IExtensionStateListener):
    """
    Ghost-Hunter Burp Extension
    
    Features:
    - Passive capture of all in-scope traffic
    - Context menu for manual "Send to Ghost-Hunter"
    - Dashboard tab with statistics
    - Batch sending to minimize API calls
    """
    
    # Configuration
    EXTENSION_NAME = "Ghost-Hunter"
    DEFAULT_API_URL = "http://127.0.0.1:1010"
    BATCH_SIZE = 10  # Send every N requests
    BATCH_TIMEOUT = 5  # Or every N seconds
    
    def registerExtenderCallbacks(self, callbacks):
        """Extension entry point - called by Burp on load."""
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        
        # Set extension name
        callbacks.setExtensionName(self.EXTENSION_NAME)
        
        # State
        self._pending_requests = []
        self._lock = threading.Lock()
        self._auto_capture = True
        self._api_url = self.DEFAULT_API_URL
        self._stats = {
            "captured": 0,
            "sent": 0,
            "new_endpoints": 0,
            "errors": 0,
            "last_send": None
        }
        self._running = True
        
        # Register listeners
        callbacks.registerHttpListener(self)
        callbacks.registerContextMenuFactory(self)
        callbacks.registerExtensionStateListener(self)
        
        # Create UI
        self._create_ui()
        callbacks.addSuiteTab(self)
        
        # Start background sender thread
        self._sender_thread = threading.Thread(target=self._batch_sender_loop)
        self._sender_thread.daemon = True
        self._sender_thread.start()
        
        self._log("[+] Ghost-Hunter extension loaded!")
        self._log("[*] API endpoint: %s/api/burp/import" % self._api_url)
        self._log("[*] Auto-capture: %s" % ("ON" if self._auto_capture else "OFF"))
    
    def extensionUnloaded(self):
        """Called when extension is unloaded."""
        self._running = False
        self._log("[*] Ghost-Hunter extension unloaded")
    
    # ==================== HTTP Listener ====================
    
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        """
        Called for every HTTP message.
        We only process responses (to get status codes).
        """
        # Only process responses
        if messageIsRequest:
            return
        
        # Check auto-capture
        if not self._auto_capture:
            return
        
        # Check if in-scope
        request_info = self._helpers.analyzeRequest(messageInfo)
        url = request_info.getUrl()
        
        if not self._callbacks.isInScope(url):
            return
        
        # Parse and queue
        try:
            request_data = self._parse_http_message(messageInfo)
            with self._lock:
                self._pending_requests.append(request_data)
                self._stats["captured"] += 1
            
            self._update_ui_stats()
            
            # Send immediately if batch is full
            if len(self._pending_requests) >= self.BATCH_SIZE:
                self._send_batch()
                
        except Exception as e:
            self._log("[!] Error parsing request: %s" % str(e))
    
    def _parse_http_message(self, messageInfo):
        """Convert Burp HTTP message to Ghost-Hunter format."""
        request_info = self._helpers.analyzeRequest(messageInfo)
        
        # Parse request
        request_bytes = messageInfo.getRequest()
        headers = {}
        raw_headers = request_info.getHeaders()
        
        # Skip first line (GET /path HTTP/1.1)
        for header in raw_headers[1:]:
            if ": " in header:
                key, value = header.split(": ", 1)
                headers[key] = value
        
        # Get body
        body_offset = request_info.getBodyOffset()
        body = None
        if body_offset < len(request_bytes):
            body_bytes = request_bytes[body_offset:]
            try:
                body = self._helpers.bytesToString(body_bytes)
            except:
                body = str(body_bytes)
        
        # Parse response if available
        response_data = None
        response_bytes = messageInfo.getResponse()
        if response_bytes:
            response_info = self._helpers.analyzeResponse(response_bytes)
            
            # Extract response body
            response_body = None
            response_body_offset = response_info.getBodyOffset()
            if response_body_offset < len(response_bytes):
                response_body_bytes = response_bytes[response_body_offset:]
                try:
                    response_body = self._helpers.bytesToString(response_body_bytes)
                    # Limit body size to 10KB to avoid huge payloads
                    if response_body and len(response_body) > 10000:
                        response_body = response_body[:10000] + "... [TRUNCATED]"
                except:
                    response_body = None
            
            response_data = {
                "status_code": response_info.getStatusCode(),
                "headers": {},
                "body": response_body  # Now includes the actual body!
            }
            # Response headers
            for header in response_info.getHeaders()[1:]:
                if ": " in header:
                    k, v = header.split(": ", 1)
                    response_data["headers"][k] = v
        
        return {
            "method": request_info.getMethod(),
            "url": str(request_info.getUrl()),
            "headers": headers,
            "body": body,
            "response": response_data
        }
    
    # ==================== Context Menu ====================
    
    def createMenuItems(self, invocation):
        """Create right-click menu items."""
        from javax.swing import JMenuItem
        
        menu_items = []
        
        # Send to Ghost-Hunter
        item = JMenuItem("Send to Ghost-Hunter")
        item.addActionListener(lambda e: self._send_selected(invocation))
        menu_items.append(item)
        
        # Send and analyze immediately
        item2 = JMenuItem("Analyze with Ghost-Hunter AI")
        item2.addActionListener(lambda e: self._send_and_analyze(invocation))
        menu_items.append(item2)
        
        return menu_items
    
    def _send_selected(self, invocation):
        """Send selected requests to Ghost-Hunter."""
        messages = invocation.getSelectedMessages()
        if not messages:
            return
        
        for message in messages:
            try:
                request_data = self._parse_http_message(message)
                with self._lock:
                    self._pending_requests.append(request_data)
                    self._stats["captured"] += 1
            except Exception as e:
                self._log("[!] Error: %s" % str(e))
        
        # Send immediately
        self._send_batch()
        self._update_ui_stats()
    
    def _send_and_analyze(self, invocation):
        """Send and trigger immediate AI analysis."""
        self._send_selected(invocation)
        # TODO: Trigger immediate triage via API
        self._log("[*] Requests sent for AI analysis")
    
    # ==================== Batch Sender ====================
    
    def _batch_sender_loop(self):
        """Background thread that sends batches periodically."""
        last_send = time.time()
        
        while self._running:
            time.sleep(1)
            
            # Send if timeout reached and we have pending requests
            if self._pending_requests and (time.time() - last_send) >= self.BATCH_TIMEOUT:
                self._send_batch()
                last_send = time.time()
    
    def _send_batch(self):
        """Send pending requests to Ghost-Hunter API."""
        with self._lock:
            if not self._pending_requests:
                return
            
            to_send = self._pending_requests[:]
            self._pending_requests = []
        
        try:
            data = json.dumps({"requests": to_send})
            
            req = Request(
                self._api_url + "/api/burp/import",
                data.encode('utf-8'),
                {"Content-Type": "application/json"}
            )
            
            response = urlopen(req, timeout=10)
            result = json.loads(response.read().decode('utf-8'))
            
            with self._lock:
                self._stats["sent"] += len(to_send)
                self._stats["new_endpoints"] += result.get("new_endpoints", 0)
                self._stats["last_send"] = time.strftime("%H:%M:%S")
            
            self._log("[+] Sent %d requests -> %d new endpoints" % (
                len(to_send), result.get("new_endpoints", 0)
            ))
            
        except URLError as e:
            self._log("[!] API Error: %s" % str(e))
            self._log("[!] Is Ghost-Hunter running? Check: %s" % self._api_url)
            with self._lock:
                self._stats["errors"] += 1
                # Re-queue failed requests
                self._pending_requests = to_send + self._pending_requests
                
        except Exception as e:
            self._log("[!] Error sending batch: %s" % str(e))
            with self._lock:
                self._stats["errors"] += 1
        
        self._update_ui_stats()
    
    # ==================== UI ====================
    
    def _create_ui(self):
        """Create the Ghost-Hunter tab UI."""
        self._panel = JPanel(BorderLayout())
        self._panel.setBorder(EmptyBorder(10, 10, 10, 10))
        
        # Header
        header = JPanel(FlowLayout(FlowLayout.LEFT))
        title = JLabel("[GH] Ghost-Hunter - AI Bug Bounty Assistant")
        title.setFont(Font("Arial", Font.BOLD, 16))
        header.add(title)
        self._panel.add(header, BorderLayout.NORTH)
        
        # Main content
        content = JPanel()
        content.setLayout(BoxLayout(content, BoxLayout.Y_AXIS))
        
        # === Config Section ===
        config_panel = JPanel(GridLayout(3, 2, 5, 5))
        config_panel.setBorder(BorderFactory.createTitledBorder("Configuration"))
        
        config_panel.add(JLabel("API URL:"))
        self._url_field = JTextField(self._api_url)
        config_panel.add(self._url_field)
        
        config_panel.add(JLabel("Auto-capture:"))
        self._auto_checkbox = JCheckBox("Capture in-scope traffic automatically")
        self._auto_checkbox.setSelected(self._auto_capture)
        self._auto_checkbox.addActionListener(lambda e: self._toggle_auto_capture())
        config_panel.add(self._auto_checkbox)
        
        config_panel.add(JLabel(""))
        save_btn = JButton("Save & Test Connection")
        save_btn.addActionListener(lambda e: self._test_connection())
        config_panel.add(save_btn)
        
        content.add(config_panel)
        
        # === Stats Section ===
        stats_panel = JPanel(GridLayout(5, 2, 5, 5))
        stats_panel.setBorder(BorderFactory.createTitledBorder("Statistics"))
        
        stats_panel.add(JLabel("Captured:"))
        self._captured_label = JLabel("0")
        stats_panel.add(self._captured_label)
        
        stats_panel.add(JLabel("Sent:"))
        self._sent_label = JLabel("0")
        stats_panel.add(self._sent_label)
        
        stats_panel.add(JLabel("New Endpoints:"))
        self._endpoints_label = JLabel("0")
        stats_panel.add(self._endpoints_label)
        
        stats_panel.add(JLabel("Errors:"))
        self._errors_label = JLabel("0")
        stats_panel.add(self._errors_label)
        
        stats_panel.add(JLabel("Last Send:"))
        self._last_send_label = JLabel("-")
        stats_panel.add(self._last_send_label)
        
        content.add(stats_panel)
        
        # === Actions Section ===
        actions_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        actions_panel.setBorder(BorderFactory.createTitledBorder("Actions"))
        
        send_btn = JButton("Send Now")
        send_btn.addActionListener(lambda e: self._send_batch())
        actions_panel.add(send_btn)
        
        clear_btn = JButton("Clear Queue")
        clear_btn.addActionListener(lambda e: self._clear_queue())
        actions_panel.add(clear_btn)
        
        dashboard_btn = JButton("Open Dashboard")
        dashboard_btn.addActionListener(lambda e: self._open_dashboard())
        actions_panel.add(dashboard_btn)
        
        content.add(actions_panel)
        
        # === Log Section ===
        log_panel = JPanel(BorderLayout())
        log_panel.setBorder(BorderFactory.createTitledBorder("Log"))
        
        self._log_area = JTextArea(10, 50)
        self._log_area.setEditable(False)
        self._log_area.setFont(Font("Monospaced", Font.PLAIN, 11))
        scroll = JScrollPane(self._log_area)
        log_panel.add(scroll, BorderLayout.CENTER)
        
        content.add(log_panel)
        
        self._panel.add(content, BorderLayout.CENTER)
    
    def _update_ui_stats(self):
        """Update UI statistics labels."""
        try:
            self._captured_label.setText(str(self._stats["captured"]))
            self._sent_label.setText(str(self._stats["sent"]))
            self._endpoints_label.setText(str(self._stats["new_endpoints"]))
            self._errors_label.setText(str(self._stats["errors"]))
            if self._stats["last_send"]:
                self._last_send_label.setText(self._stats["last_send"])
        except:
            pass
    
    def _log(self, message):
        """Add message to log area."""
        timestamp = time.strftime("[%H:%M:%S] ")
        try:
            self._log_area.append(timestamp + message + "\n")
            # Auto-scroll
            self._log_area.setCaretPosition(self._log_area.getDocument().getLength())
        except:
            pass
        # Also print to Burp output
        print(message)
    
    def _toggle_auto_capture(self):
        """Toggle auto-capture mode."""
        self._auto_capture = self._auto_checkbox.isSelected()
        self._log("[*] Auto-capture: %s" % ("ON" if self._auto_capture else "OFF"))
    
    def _test_connection(self):
        """Test connection to Ghost-Hunter API."""
        self._api_url = self._url_field.getText().strip().rstrip("/")
        
        try:
            req = Request(self._api_url + "/api/burp/status")
            response = urlopen(req, timeout=5)
            result = json.loads(response.read().decode('utf-8'))
            
            if result.get("connected"):
                self._log("[+] Connection OK! Total endpoints: %d" % result.get("total_endpoints", 0))
                JOptionPane.showMessageDialog(
                    self._panel,
                    "Connected to Ghost-Hunter!\nTotal endpoints: %d" % result.get("total_endpoints", 0),
                    "Success",
                    JOptionPane.INFORMATION_MESSAGE
                )
            else:
                raise Exception(result.get("error", "Unknown error"))
                
        except Exception as e:
            self._log("[!] Connection failed: %s" % str(e))
            JOptionPane.showMessageDialog(
                self._panel,
                "Failed to connect to Ghost-Hunter:\n%s\n\nMake sure Ghost-Hunter is running!" % str(e),
                "Error",
                JOptionPane.ERROR_MESSAGE
            )
    
    def _clear_queue(self):
        """Clear pending requests queue."""
        with self._lock:
            count = len(self._pending_requests)
            self._pending_requests = []
        self._log("[*] Cleared %d pending requests" % count)
    
    def _open_dashboard(self):
        """Open Ghost-Hunter dashboard in browser."""
        try:
            import webbrowser
            webbrowser.open(self._api_url + "/dashboard")
        except:
            self._log("[!] Could not open browser. Visit: %s/dashboard" % self._api_url)
    
    # ==================== ITab ====================
    
    def getTabCaption(self):
        """Tab title in Burp."""
        return "Ghost-Hunter"
    
    def getUiComponent(self):
        """Tab content panel."""
        return self._panel
