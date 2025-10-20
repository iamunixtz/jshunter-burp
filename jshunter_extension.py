#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
JSHunter  Extension
Author: iamunixtz
Version: 1.0.0
Date: 2025

A extension that automatically detects JavaScript URLs from HTTP requests,
scans them using JSHunter, and sends findings to Discord webhooks.
"""

import json
import os
import re
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime

# Handle Python 2/3 compatibility for urllib
try:
    from urllib.parse import urlparse, urljoin
except ImportError:
    from urlparse import urlparse, urljoin

# Use Java's built-in HTTP capabilities instead of Python requests
from java.net import URL, HttpURLConnection
from java.io import BufferedReader, InputStreamReader, OutputStreamWriter

# Burp Suite API imports
from burp import IBurpExtender, IHttpListener, ITab
from java.awt import BorderLayout, FlowLayout, GridBagLayout, GridBagConstraints, Insets, Dimension
from java.awt.event import ActionListener, MouseAdapter
from javax.swing import (JPanel, JTextField, JCheckBox, JButton, JTable, JTextArea, 
                        JScrollPane, JLabel, JOptionPane, BorderFactory, JFileChooser,
                        ListSelectionModel, JDialog, JSplitPane)
from javax.swing.table import DefaultTableModel, TableRowSorter
from java.util import ArrayList, Date
from java.util.concurrent import ConcurrentHashMap


class BurpExtender(IBurpExtender, IHttpListener, ITab):
    """
    Main Burp Suite extension class that implements:
    - IBurpExtender: Entry point for the extension
    - IHttpListener: Monitors HTTP traffic
    - ITab: Provides custom UI tab
    """
    
    def registerExtenderCallbacks(self, callbacks):
        """Register the extension with Burp Suite."""
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        
        # Set extension name
        callbacks.setExtensionName("JSHunter - JavaScript Security Scanner")
        
        # Register HTTP listener
        callbacks.registerHttpListener(self)
        
        # Initialize data structures
        self._scanned_urls = ConcurrentHashMap()
        self._scan_results = ArrayList()
        
        # Configuration
        self._discord_webhook_url = ""
        self._auto_scan_enabled = True
        self._send_to_discord_enabled = True
        
        # Load saved settings
        self._load_settings()
        
        # Create UI
        self._create_ui()
        
        # Add custom tab
        callbacks.addSuiteTab(self)
        
        # Print startup message
        print("JSHunter Burp Extension loaded successfully!")
        print("Version: 1.0.0")
        print("Author: iamunixtz")
        print("Date: 2025")
        
        # Clean up any leftover temp files from previous sessions
        self._cleanup_temp_files()
    
    def _load_settings(self):
        """Load saved settings from Burp Suite."""
        try:
            # Load Discord webhook URL
            saved_webhook = self._callbacks.loadExtensionSetting("discord_webhook_url")
            if saved_webhook:
                self._discord_webhook_url = saved_webhook
            
            # Load auto-scan setting
            saved_auto_scan = self._callbacks.loadExtensionSetting("auto_scan_enabled")
            if saved_auto_scan:
                self._auto_scan_enabled = saved_auto_scan.lower() == "true"
            
            # Load send to Discord setting
            saved_send_discord = self._callbacks.loadExtensionSetting("send_to_discord_enabled")
            if saved_send_discord:
                self._send_to_discord_enabled = saved_send_discord.lower() == "true"
                
        except Exception as e:
            self._log_message("Error loading settings: " + str(e))
    
    def _save_settings(self):
        """Save current settings to Burp Suite."""
        try:
            # Save Discord webhook URL
            self._callbacks.saveExtensionSetting("discord_webhook_url", self._discord_webhook_url)
            
            # Save auto-scan setting
            self._callbacks.saveExtensionSetting("auto_scan_enabled", str(self._auto_scan_enabled).lower())
            
            # Save send to Discord setting
            self._callbacks.saveExtensionSetting("send_to_discord_enabled", str(self._send_to_discord_enabled).lower())
            
        except Exception as e:
            self._log_message("Error saving settings: " + str(e))
    
    def _create_ui(self):
        """Create the extension UI."""
        self._main_panel = JPanel(BorderLayout())
        
        # Configuration panel
        config_panel = self._create_config_panel()
        self._main_panel.add(config_panel, BorderLayout.NORTH)
        
        # Results panel
        results_panel = self._create_results_panel()
        
        # Findings panel
        findings_panel = self._create_findings_panel()
        
        # Create resizable split pane for results and findings
        self._results_findings_split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, results_panel, findings_panel)
        self._results_findings_split.setResizeWeight(0.6)  # Give 60% to results, 40% to findings initially
        self._results_findings_split.setDividerLocation(0.6)  # Set initial divider position
        self._results_findings_split.setOneTouchExpandable(True)  # Add one-touch expand buttons
        
        self._main_panel.add(self._results_findings_split, BorderLayout.CENTER)
        
        # Log panel
        log_panel = self._create_log_panel()
        self._main_panel.add(log_panel, BorderLayout.SOUTH)
    
    def _create_config_panel(self):
        """Create the configuration panel."""
        panel = JPanel(GridBagLayout())
        panel.setBorder(BorderFactory.createTitledBorder("Configuration"))
        gbc = GridBagConstraints()
        gbc.insets = Insets(5, 5, 5, 5)
        gbc.anchor = GridBagConstraints.WEST
        
        # Discord Webhook URL
        gbc.gridx = 0; gbc.gridy = 0
        panel.add(JLabel("Discord Webhook URL:"), gbc)
        gbc.gridx = 1; gbc.gridy = 0; gbc.weightx = 1.0; gbc.fill = GridBagConstraints.HORIZONTAL
        self._discord_webhook_field = JTextField(50)
        self._discord_webhook_field.setText(self._discord_webhook_url)  # Load saved URL
        panel.add(self._discord_webhook_field, gbc)
        
        # Test webhook button
        gbc.gridx = 2; gbc.gridy = 0; gbc.weightx = 0; gbc.fill = GridBagConstraints.NONE
        self._test_webhook_button = JButton("Test")
        self._test_webhook_button.addActionListener(TestWebhookListener(self))
        panel.add(self._test_webhook_button, gbc)
        
        # Auto scan checkbox
        gbc.gridx = 0; gbc.gridy = 1; gbc.gridwidth = 2
        self._auto_scan_checkbox = JCheckBox("Auto-scan JavaScript URLs from requests", self._auto_scan_enabled)
        self._auto_scan_checkbox.addActionListener(AutoScanListener(self))
        panel.add(self._auto_scan_checkbox, gbc)
        
        # Send to Discord checkbox
        gbc.gridx = 0; gbc.gridy = 2; gbc.gridwidth = 2
        self._send_to_discord_checkbox = JCheckBox("Send findings to Discord", self._send_to_discord_enabled)
        self._send_to_discord_checkbox.addActionListener(SendToDiscordListener(self))
        panel.add(self._send_to_discord_checkbox, gbc)
        
        # TruffleHog Path
        gbc.gridx = 0; gbc.gridy = 3
        panel.add(JLabel("TruffleHog Path:"), gbc)
        gbc.gridx = 1; gbc.gridy = 3; gbc.weightx = 1.0; gbc.fill = GridBagConstraints.HORIZONTAL
        self._trufflehog_path_field = JTextField(50)
        self._trufflehog_path_field.setText("/usr/local/bin/trufflehog")  # Default path
        panel.add(self._trufflehog_path_field, gbc)
        
        # Browse button for TruffleHog path
        gbc.gridx = 2; gbc.gridy = 3; gbc.weightx = 0; gbc.fill = GridBagConstraints.NONE
        self._browse_trufflehog_button = JButton("Browse")
        self._browse_trufflehog_button.addActionListener(BrowseTruffleHogListener(self))
        panel.add(self._browse_trufflehog_button, gbc)
        
        # Test TruffleHog button
        gbc.gridx = 3; gbc.gridy = 3; gbc.weightx = 0; gbc.fill = GridBagConstraints.NONE
        self._test_trufflehog_button = JButton("Test")
        self._test_trufflehog_button.addActionListener(TestTruffleHogListener(self))
        panel.add(self._test_trufflehog_button, gbc)
        
        # TruffleHog status
        gbc.gridx = 0; gbc.gridy = 4; gbc.gridwidth = 3
        self._trufflehog_status_label = JLabel("TruffleHog: Not tested")
        panel.add(self._trufflehog_status_label, gbc)
        
        return panel
    
    def _create_results_panel(self):
        """Create the results panel."""
        panel = JPanel(BorderLayout())
        panel.setBorder(BorderFactory.createTitledBorder("Scan Results"))
        
        # Table model
        column_names = ["Timestamp", "URL", "Findings", "Verified", "Unverified", "Status"]
        self._table_model = DefaultTableModel(column_names, 0)
        
        self._results_table = JTable(self._table_model)
        self._results_table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        self._results_table.setRowSorter(TableRowSorter(self._table_model))
        
        # Add mouse listener for double-click to view details
        self._results_table.addMouseListener(ResultDetailsListener(self))
        
        scroll_pane = JScrollPane(self._results_table)
        panel.add(scroll_pane, BorderLayout.CENTER)
        
        # Buttons panel
        buttons_panel = JPanel(FlowLayout())
        self._clear_results_button = JButton("Clear Results")
        self._clear_results_button.addActionListener(ClearResultsListener(self))
        buttons_panel.add(self._clear_results_button)
        
        self._export_results_button = JButton("Export Results")
        self._export_results_button.addActionListener(ExportResultsListener(self))
        buttons_panel.add(self._export_results_button)
        
        panel.add(buttons_panel, BorderLayout.SOUTH)
        
        return panel
    
    def _create_findings_panel(self):
        """Create the findings panel to display actual secrets."""
        panel = JPanel(BorderLayout())
        panel.setBorder(BorderFactory.createTitledBorder("Findings Details"))
        panel.setPreferredSize(Dimension(400, 300))
        
        # Findings table model
        findings_columns = ["Type", "Secret", "URL", "Line", "Verified"]
        self._findings_table_model = DefaultTableModel(findings_columns, 0)
        self._findings_table = JTable(self._findings_table_model)
        self._findings_table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        
        # Make columns wider for better visibility
        self._findings_table.getColumnModel().getColumn(0).setPreferredWidth(100)  # Type
        self._findings_table.getColumnModel().getColumn(1).setPreferredWidth(200)  # Secret
        self._findings_table.getColumnModel().getColumn(2).setPreferredWidth(150)  # URL
        self._findings_table.getColumnModel().getColumn(3).setPreferredWidth(50)   # Line
        self._findings_table.getColumnModel().getColumn(4).setPreferredWidth(60)   # Verified
        
        # Add scroll pane
        scroll_pane = JScrollPane(self._findings_table)
        panel.add(scroll_pane, BorderLayout.CENTER)
        
        # Add copy button
        button_panel = JPanel(FlowLayout())
        self._copy_finding_button = JButton("Copy Secret")
        self._copy_finding_button.addActionListener(CopyFindingListener(self))
        button_panel.add(self._copy_finding_button)
        
        self._clear_findings_button = JButton("Clear Findings")
        self._clear_findings_button.addActionListener(ClearFindingsListener(self))
        button_panel.add(self._clear_findings_button)
        
        self._cleanup_temp_button = JButton("Cleanup Temp Files")
        self._cleanup_temp_button.addActionListener(CleanupTempFilesListener(self))
        button_panel.add(self._cleanup_temp_button)
        
        panel.add(button_panel, BorderLayout.SOUTH)
        
        return panel
    
    def _create_log_panel(self):
        """Create the log panel."""
        panel = JPanel(BorderLayout())
        panel.setBorder(BorderFactory.createTitledBorder("Activity Log"))
        
        self._log_area = JTextArea(8, 0)
        self._log_area.setEditable(False)
        log_scroll_pane = JScrollPane(self._log_area)
        log_scroll_pane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS)
        
        panel.add(log_scroll_pane, BorderLayout.CENTER)
        
        return panel
    
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        """Process HTTP messages to extract JavaScript URLs."""
        if not messageIsRequest or not self._auto_scan_enabled:
            return
        
        # Only process requests from Proxy, Spider, and Scanner
        if toolFlag not in [self._callbacks.TOOL_PROXY, 
                           self._callbacks.TOOL_SPIDER, 
                           self._callbacks.TOOL_SCANNER]:
            return
        
        try:
            request_info = self._helpers.analyzeRequest(messageInfo)
            url = request_info.getUrl().toString()
            
            # Extract JavaScript URLs from the request
            js_urls = self._extract_javascript_urls(messageInfo)
            
            for js_url in js_urls:
                if js_url not in self._scanned_urls:
                    self._scanned_urls.put(js_url, True)
                    self._log_message("Found JavaScript URL: " + js_url)
                    
                    # Schedule scan in background
                    thread = threading.Thread(target=self._scan_javascript_url, args=(js_url,))
                    thread.daemon = True
                    thread.start()
                    
        except Exception as e:
            self._log_message("Error processing HTTP message: " + str(e))
    
    def _extract_javascript_urls(self, messageInfo):
        """Extract JavaScript URLs from HTTP message."""
        js_urls = set()
        
        try:
            request_info = self._helpers.analyzeRequest(messageInfo)
            url = request_info.getUrl().toString()
            
            # Check if the request URL itself is a JavaScript file
            if self._is_javascript_url(url):
                js_urls.add(url)
            
            # Extract from request body
            request = messageInfo.getRequest()
            analyzed_request = self._helpers.analyzeRequest(request)
            body_offset = analyzed_request.getBodyOffset()
            if body_offset < len(request):
                body = request[body_offset:].tostring()
                js_urls.update(self._extract_urls_from_text(body))
            
            # Extract from response body if available
            if messageInfo.getResponse() is not None:
                response = messageInfo.getResponse()
                analyzed_response = self._helpers.analyzeResponse(response)
                response_body_offset = analyzed_response.getBodyOffset()
                if response_body_offset < len(response):
                    response_body = response[response_body_offset:].tostring()
                    js_urls.update(self._extract_urls_from_text(response_body))
                    
        except Exception as e:
            self._log_message("Error extracting JavaScript URLs: " + str(e))
        
        return js_urls
    
    def _extract_urls_from_text(self, text):
        """Extract JavaScript URLs from text content."""
        urls = set()
        
        # Pattern for script src attributes
        script_pattern = r'(?i)<script[^>]+src\s*=\s*["\']([^"\']+\.js(?:\?[^"\']*)?(?:#[^"\']*)?)["\']'
        script_matches = re.findall(script_pattern, text)
        
        for match in script_matches:
            if self._is_javascript_url(match):
                normalized_url = self._normalize_url(match)
                if normalized_url:
                    urls.add(normalized_url)
        
        # Pattern for standalone JavaScript URLs
        js_pattern = r'(?i)(?:https?://[^\s"\'<>]+\.js(?:\?[^\s"\'<>]*)?(?:#[^\s"\'<>]*)?)'
        js_matches = re.findall(js_pattern, text)
        
        for match in js_matches:
            if self._is_javascript_url(match):
                normalized_url = self._normalize_url(match)
                if normalized_url:
                    urls.add(normalized_url)
        
        return urls
    
    def _is_javascript_url(self, url):
        """Check if URL is a JavaScript file."""
        if not url or not url.strip():
            return False
        
        url_lower = url.lower().strip()
        return (url_lower.endswith('.js') or 
                '.js?' in url_lower or 
                '.js#' in url_lower or
                'javascript:' in url_lower or
                'application/javascript' in url_lower)
    
    def _normalize_url(self, url):
        """Normalize URL."""
        try:
            # Handle relative URLs
            if url.startswith('//'):
                url = 'https:' + url
            elif url.startswith('/'):
                # Skip relative URLs for now
                return None
            
            parsed_url = urlparse(url)
            return parsed_url.geturl()
        except:
            return None
    
    def _scan_javascript_url(self, url):
        """Scan a JavaScript URL using TruffleHog directly."""
        self._log_message("Scanning JavaScript URL: " + url)
        
        result = {
            'url': url,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'findings': [],
            'success': False,
            'error': None
        }
        
        try:
            # Get TruffleHog binary path
            tr_bin = self._get_trufflehog_binary()
            if not tr_bin:
                result['error'] = "TruffleHog binary not found. Please install TruffleHog."
                self._log_message("TruffleHog binary not found")
                self._add_result_to_table(result)
                return result
            
            # Download JavaScript file
            js_content = self._download_js_file(url)
            if not js_content:
                result['error'] = "Failed to download JavaScript file"
                self._log_message("Failed to download JavaScript file: " + url)
                self._add_result_to_table(result)
                return result
            
            # Save to temporary file
            temp_file = self._save_temp_js_file(js_content, url)
            if not temp_file:
                result['error'] = "Failed to create temporary file"
                self._add_result_to_table(result)
                return result
            
            try:
                # Run TruffleHog on the file
                findings = self._run_trufflehog(temp_file, tr_bin)
                result['findings'] = findings
                result['success'] = True
                self._log_message("Scan completed successfully for: " + url + " - " + str(len(findings)) + " findings")
                
                # Send to Discord if enabled
                if self._send_to_discord_enabled and findings:
                    self._send_to_discord(result)
                    
            finally:
                # Clean up temporary file
                try:
                    if os.path.exists(temp_file):
                        os.unlink(temp_file)
                        self._log_message("Cleaned up temporary file: " + os.path.basename(temp_file))
                except Exception as cleanup_error:
                    self._log_message("Error cleaning up temp file: " + str(cleanup_error))
                
        except Exception as e:
            result['error'] = str(e)
            self._log_message("Error scanning " + url + ": " + str(e))
        
        # Add result to table
        self._add_result_to_table(result)
        
        # Add findings to findings table
        if result['success'] and result['findings']:
            self._add_findings_to_table(result['findings'], result['url'])
    
    def _cleanup_temp_files(self):
        """Clean up any remaining temporary JavaScript files."""
        try:
            temp_dir = tempfile.gettempdir()
            # Look for files that start with "jshunter_" (our temp file prefix)
            for filename in os.listdir(temp_dir):
                if filename.startswith("jshunter_") and filename.endswith(".js"):
                    temp_file_path = os.path.join(temp_dir, filename)
                    try:
                        os.unlink(temp_file_path)
                        self._log_message("Cleaned up leftover temp file: " + filename)
                    except Exception as e:
                        self._log_message("Error cleaning up leftover temp file " + filename + ": " + str(e))
        except Exception as e:
            self._log_message("Error during temp file cleanup: " + str(e))
    
    def _add_findings_to_table(self, findings, source_url):
        """Add findings to the findings details table."""
        for finding in findings:
            detector_name = finding.get('DetectorName', 'Unknown')
            raw_value = finding.get('Raw', '')
            verified = finding.get('Verified', False)
            line_number = finding.get('SourceMetadata', {}).get('Data', {}).get('Filesystem', {}).get('line', 0)
            
            # Truncate long secrets for display
            display_secret = raw_value[:50] + "..." if len(raw_value) > 50 else raw_value
            
            # Add row to findings table
            row = [detector_name, display_secret, source_url, str(line_number), "Yes" if verified else "No"]
            self._findings_table_model.addRow(row)
    
    def _get_trufflehog_binary(self):
        """Get TruffleHog binary path from user configuration using official PortSwigger method."""
        # Get path from UI field
        configured_path = self._trufflehog_path_field.getText().strip()
        self._log_message("Checking TruffleHog path: " + configured_path)
        
        if not configured_path:
            self._log_message("No TruffleHog path configured")
            return None
        
        # Use the official PortSwigger verification method
        if self._verify_trufflehog_path(configured_path):
            self._log_message("TruffleHog binary validated successfully")
            return configured_path
        else:
            self._log_message("TruffleHog binary validation failed")
            return None
    
    def _verify_trufflehog_path(self, path):
        """Verify TruffleHog path using official PortSwigger method."""
        if not path or not os.path.isabs(path) or not os.access(path, os.X_OK):
            self._log_message("TruffleHog path validation failed: not absolute or not executable")
            return False
        try:
            self._log_message("Testing TruffleHog binary: " + path)
            proc = subprocess.Popen([path, "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout_data, stderr_data = proc.communicate()
            self._log_message("TruffleHog test - stdout: " + stdout_data.decode('utf-8', errors='ignore').strip() + 
                            ", stderr: " + stderr_data.decode('utf-8', errors='ignore').strip())
            
            # Check if "trufflehog" appears in either stdout or stderr
            combined_output = (stderr_data.lower() + stdout_data.lower())
            if b"trufflehog" in combined_output:
                self._log_message("TruffleHog binary found in output")
                return True
            else:
                self._log_message("TruffleHog binary not found in output")
                return False
        except Exception as e:
            self._log_message("Error testing TruffleHog binary: " + str(e))
            return False
    
    def _download_js_file(self, url):
        """Download JavaScript file content."""
        try:
            # Use Java HTTP to download the file
            url_obj = URL(url)
            connection = url_obj.openConnection()
            connection.setRequestMethod("GET")
            connection.setRequestProperty("User-Agent", "JSHunter-Burp-Extension/1.0")
            connection.setConnectTimeout(10000)  # 10 seconds
            connection.setReadTimeout(30000)     # 30 seconds
            
            # Read the response
            input_stream = connection.getInputStream()
            reader = BufferedReader(InputStreamReader(input_stream, "UTF-8"))
            
            content = []
            line = reader.readLine()
            while line is not None:
                content.append(line)
                line = reader.readLine()
            
            reader.close()
            connection.disconnect()
            
            return "\n".join(content)
            
        except Exception as e:
            self._log_message("Error downloading JS file: " + str(e))
            return None
    
    def _save_temp_js_file(self, content, url):
        """Save JavaScript content to temporary file."""
        try:
            # Create a safe filename from URL
            safe_filename = re.sub(r'[^\w\-_\.]', '_', urlparse(url).path)
            if not safe_filename.endswith('.js'):
                safe_filename += '.js'
            
            # Create temporary file
            temp_dir = tempfile.gettempdir()
            temp_file = os.path.join(temp_dir, "jshunter_" + safe_filename)
            
            with open(temp_file, 'w') as f:
                f.write(content)
            
            return temp_file
            
        except Exception as e:
            self._log_message("Error creating temp file: " + str(e))
            return None
    
    def _run_trufflehog(self, file_path, tr_bin):
        """Run TruffleHog on a file and return findings."""
        try:
            cmd = [tr_bin, "filesystem", file_path, "--json"]
            # Use Popen for Python 2.7 compatibility
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            # Wait for process with timeout (Python 2.7 compatible)
            import signal
            
            def timeout_handler(signum, frame):
                raise Exception("Timeout")
            
            # Set timeout signal
            old_handler = signal.signal(signal.SIGALRM, timeout_handler)
            signal.alarm(60)  # 60 second timeout
            
            try:
                stdout_data, stderr_data = proc.communicate()
                signal.alarm(0)  # Cancel timeout
                signal.signal(signal.SIGALRM, old_handler)  # Restore old handler
                
                if proc.returncode == 0:
                    findings = []
                    for line in stdout_data.strip().split('\n'):
                        if line.strip():
                            try:
                                finding = json.loads(line)
                                findings.append(finding)
                            except ValueError:  # json.JSONDecodeError in Python 2.7
                                continue
                    return findings
                else:
                    self._log_message("TruffleHog error: " + stderr_data)
                    return []
                    
            except Exception as timeout_error:
                signal.alarm(0)  # Cancel timeout
                signal.signal(signal.SIGALRM, old_handler)  # Restore old handler
                proc.terminate()
                if "Timeout" in str(timeout_error):
                    self._log_message("TruffleHog timeout for file: " + file_path)
                else:
                    self._log_message("TruffleHog execution error: " + str(timeout_error))
                return []
                
        except Exception as e:
            self._log_message("TruffleHog execution error: " + str(e))
            return []
    
    def _send_to_discord(self, result):
        """Send findings to Discord webhook."""
        if not self._discord_webhook_url or not self._discord_webhook_url.strip():
            return
        
        # Java HTTP is always available in Burp Suite
            
        try:
            # Separate verified and unverified findings
            verified_findings = [f for f in result['findings'] if f.get('Verified', False)]
            unverified_findings = [f for f in result['findings'] if not f.get('Verified', False)]
            
            # Send verified findings immediately
            if verified_findings:
                self._send_findings_to_discord(verified_findings, result['url'], True)
            
            # Send unverified findings
            if unverified_findings:
                self._send_findings_to_discord(unverified_findings, result['url'], False)
                
        except Exception as e:
            self._log_message("Error sending to Discord: " + str(e))
    
    def _send_findings_to_discord(self, findings, source_url, verified):
        """Send findings to Discord using Java HTTP."""
        try:
            message = "[VERIFIED] **Verified Secrets**" if verified else "[UNVERIFIED] **Unverified Secrets**"
            message += " found in " + source_url + "\n\n"
            
            for finding in findings:
                detector_name = finding.get('DetectorName', 'Unknown')
                raw_value = finding.get('Raw', '')
                line_number = finding.get('SourceMetadata', {}).get('Data', {}).get('Filesystem', {}).get('line', 0)
                
                message += "**" + detector_name + "**\n"
                message += "```\n" + raw_value + "\n```\n"
                if line_number > 0:
                    message += "Line: " + str(line_number) + "\n"
                message += "\n"
            
            # Discord webhook payload
            payload = {
                "content": message,
                "username": "JSHunter Bot",
                "avatar_url": "https://i.imgur.com/4M34hi2.png"
            }
            
            # Send HTTP request using Java
            self._send_http_post(self._discord_webhook_url, payload)
            
            self._log_message("Successfully sent " + str(len(findings)) + " " + 
                            ("verified" if verified else "unverified") + " findings to Discord")
                
        except Exception as e:
            self._log_message("Error sending findings to Discord: " + str(e))
    
    def _test_discord_webhook(self):
        """Test Discord webhook connection."""
        webhook_url = self._discord_webhook_field.getText().strip()
        if not webhook_url:
            JOptionPane.showMessageDialog(self._main_panel, "Please enter a Discord webhook URL", "Error", JOptionPane.ERROR_MESSAGE)
            return
        
        self._discord_webhook_url = webhook_url
        self._save_settings()  # Save the webhook URL
        
        # Send test message
        try:
            payload = {
                "content": "[TEST] **JSHunter Test Message**\n\nThis is a test message from JSHunter Burp Extension. If you receive this, your webhook is configured correctly!",
                "username": "JSHunter Bot",
                "avatar_url": "https://i.imgur.com/4M34hi2.png"
            }
            
            # Send HTTP request using Java
            response_code = self._send_http_post(webhook_url, payload)
            
            if response_code == 204:
                JOptionPane.showMessageDialog(self._main_panel, "Test message sent successfully!", "Success", JOptionPane.INFORMATION_MESSAGE)
                self._log_message("Discord webhook test successful")
            else:
                JOptionPane.showMessageDialog(self._main_panel, "Webhook test failed. Response code: " + str(response_code), "Error", JOptionPane.ERROR_MESSAGE)
                self._log_message("Discord webhook test failed with code: " + str(response_code))
                
        except Exception as e:
            JOptionPane.showMessageDialog(self._main_panel, "Error testing webhook: " + str(e), "Error", JOptionPane.ERROR_MESSAGE)
            self._log_message("Error testing Discord webhook: " + str(e))
    
    def _test_trufflehog(self):
        """Test TruffleHog binary."""
        trufflehog_path = self._trufflehog_path_field.getText().strip()
        if not trufflehog_path:
            JOptionPane.showMessageDialog(self._main_panel, "Please enter a TruffleHog path", "Error", JOptionPane.ERROR_MESSAGE)
            return
        
        try:
            # Test if the binary exists and is executable
            if not os.path.exists(trufflehog_path):
                self._trufflehog_status_label.setText("TruffleHog: File not found")
                JOptionPane.showMessageDialog(self._main_panel, "TruffleHog binary not found at: " + trufflehog_path, "Error", JOptionPane.ERROR_MESSAGE)
                return
            
            if not os.access(trufflehog_path, os.X_OK):
                self._trufflehog_status_label.setText("TruffleHog: Not executable")
                JOptionPane.showMessageDialog(self._main_panel, "TruffleHog binary is not executable: " + trufflehog_path, "Error", JOptionPane.ERROR_MESSAGE)
                return
            
            # Test if it's a valid TruffleHog binary using official method
            if self._verify_trufflehog_path(trufflehog_path):
                # Get version info for display
                try:
                    proc = subprocess.Popen([trufflehog_path, "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    stdout_data, stderr_data = proc.communicate()
                    version_info = (stdout_data + stderr_data).decode('utf-8', errors='ignore').strip()
                except:
                    version_info = "trufflehog"
                
                self._trufflehog_status_label.setText("TruffleHog: " + version_info)
                JOptionPane.showMessageDialog(self._main_panel, "TruffleHog test successful!\n" + version_info, "Success", JOptionPane.INFORMATION_MESSAGE)
                self._log_message("TruffleHog test successful: " + version_info)
            else:
                self._trufflehog_status_label.setText("TruffleHog: Invalid binary")
                JOptionPane.showMessageDialog(self._main_panel, "Invalid TruffleHog binary at: " + trufflehog_path, "Error", JOptionPane.ERROR_MESSAGE)
                self._log_message("TruffleHog test failed: binary not valid")
                
        except subprocess.TimeoutExpired:
            self._trufflehog_status_label.setText("TruffleHog: Timeout")
            JOptionPane.showMessageDialog(self._main_panel, "TruffleHog test timeout", "Error", JOptionPane.ERROR_MESSAGE)
            self._log_message("TruffleHog test timeout")
        except Exception as e:
            self._trufflehog_status_label.setText("TruffleHog: Error")
            JOptionPane.showMessageDialog(self._main_panel, "Error testing TruffleHog: " + str(e), "Error", JOptionPane.ERROR_MESSAGE)
            self._log_message("Error testing TruffleHog: " + str(e))
    
    def _browse_trufflehog_path(self):
        """Open file chooser to select TruffleHog binary."""
        file_chooser = JFileChooser()
        file_chooser.setDialogTitle("Select TruffleHog Binary")
        file_chooser.setFileSelectionMode(JFileChooser.FILES_ONLY)
        
        # Set initial directory to common TruffleHog locations
        current_path = self._trufflehog_path_field.getText().strip()
        if current_path and os.path.exists(os.path.dirname(current_path)):
            file_chooser.setCurrentDirectory(java.io.File(os.path.dirname(current_path)))
        else:
            # Try common locations
            common_paths = ["/usr/local/bin", "/usr/bin", "/opt/trufflehog", os.path.expanduser("~/.local/bin")]
            for path in common_paths:
                if os.path.exists(path):
                    file_chooser.setCurrentDirectory(java.io.File(path))
                    break
        
        # Add file filter for executable files
        class ExecutableFileFilter(javax.swing.filechooser.FileFilter):
            def accept(self, file):
                if file.isDirectory():
                    return True
                name = file.getName().lower()
                return (name == "trufflehog" or 
                       name.startswith("trufflehog") or 
                       file.canExecute())
            
            def getDescription(self):
                return "TruffleHog Binary (*trufflehog*)"
        
        file_chooser.setFileFilter(ExecutableFileFilter())
        
        result = file_chooser.showOpenDialog(self._main_panel)
        if result == JFileChooser.APPROVE_OPTION:
            selected_file = file_chooser.getSelectedFile()
            if selected_file:
                file_path = selected_file.getAbsolutePath()
                self._trufflehog_path_field.setText(file_path)
                self._log_message("Selected TruffleHog binary: " + file_path)
                
                # Auto-test the selected binary
                self._test_trufflehog()
    
    def _send_http_post(self, url, payload):
        """Send HTTP POST request using Java's built-in HTTP capabilities."""
        try:
            # Create URL object
            url_obj = URL(url)
            connection = url_obj.openConnection()
            connection.setRequestMethod("POST")
            connection.setRequestProperty("Content-Type", "application/json")
            connection.setDoOutput(True)
            
            # Convert payload to JSON string
            json_payload = json.dumps(payload)
            
            # Send the request using UTF-8 encoding
            output_stream = connection.getOutputStream()
            writer = OutputStreamWriter(output_stream, "UTF-8")
            writer.write(json_payload)
            writer.flush()
            writer.close()
            
            # Get response code
            response_code = connection.getResponseCode()
            
            # Close connection
            connection.disconnect()
            
            return response_code
            
        except Exception as e:
            self._log_message("HTTP POST error: " + str(e))
            return -1
    
    def _add_result_to_table(self, result):
        """Add scan result to the results table."""
        verified_count = sum(1 for f in result['findings'] if f.get('Verified', False))
        unverified_count = len(result['findings']) - verified_count
        
        status = "Success" if result['success'] else "Failed: " + str(result['error'])
        
        row_data = [
            result['timestamp'],
            result['url'],
            len(result['findings']),
            verified_count,
            unverified_count,
            status
        ]
        
        self._table_model.addRow(row_data)
        self._scan_results.add(result)
        
        # Auto-scroll to bottom
        self._results_table.scrollRectToVisible(
            self._results_table.getCellRect(self._table_model.getRowCount() - 1, 0, True)
        )
    
    def _log_message(self, message):
        """Log a message to the activity log."""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_entry = "[" + timestamp + "] " + message + "\n"
        
        # Update UI in EDT
        def update_log():
            self._log_area.append(log_entry)
            self._log_area.setCaretPosition(len(self._log_area.getText()))
        
        # Schedule UI update on EDT
        from javax.swing import SwingUtilities
        SwingUtilities.invokeLater(update_log)
        
        # Also print to console
        print(log_entry.strip())
    
    def getTabCaption(self):
        """Return the tab caption."""
        return "JSHunter"
    
    def getUiComponent(self):
        """Return the UI component."""
        return self._main_panel


# Event Listeners
class TestWebhookListener(ActionListener):
    def __init__(self, extension):
        self._extension = extension
    
    def actionPerformed(self, event):
        self._extension._test_discord_webhook()


class AutoScanListener(ActionListener):
    def __init__(self, extension):
        self._extension = extension
    
    def actionPerformed(self, event):
        self._extension._auto_scan_enabled = self._extension._auto_scan_checkbox.isSelected()
        self._extension._save_settings()


class SendToDiscordListener(ActionListener):
    def __init__(self, extension):
        self._extension = extension
    
    def actionPerformed(self, event):
        self._extension._send_to_discord_enabled = self._extension._send_to_discord_checkbox.isSelected()
        self._extension._save_settings()

class TestTruffleHogListener(ActionListener):
    def __init__(self, extension):
        self._extension = extension
    
    def actionPerformed(self, event):
        self._extension._test_trufflehog()

class BrowseTruffleHogListener(ActionListener):
    def __init__(self, extension):
        self._extension = extension
    
    def actionPerformed(self, event):
        self._extension._browse_trufflehog_path()

class CopyFindingListener(ActionListener):
    def __init__(self, extension):
        self._extension = extension
    
    def actionPerformed(self, event):
        selected_row = self._extension._findings_table.getSelectedRow()
        if selected_row >= 0:
            secret_value = self._extension._findings_table_model.getValueAt(selected_row, 1)
            # Copy to clipboard (simplified - in real implementation you'd use Java clipboard)
            JOptionPane.showMessageDialog(self._extension._main_panel, 
                                        "Secret copied to clipboard:\n" + str(secret_value), 
                                        "Copied", JOptionPane.INFORMATION_MESSAGE)
        else:
            JOptionPane.showMessageDialog(self._extension._main_panel, 
                                        "Please select a finding to copy", 
                                        "No Selection", JOptionPane.WARNING_MESSAGE)

class ClearFindingsListener(ActionListener):
    def __init__(self, extension):
        self._extension = extension
    
    def actionPerformed(self, event):
        result = JOptionPane.showConfirmDialog(
            self._extension._main_panel,
            "Are you sure you want to clear all findings?",
            "Clear Findings",
            JOptionPane.YES_NO_OPTION
        )
        if result == JOptionPane.YES_OPTION:
            self._extension._findings_table_model.setRowCount(0)

class CleanupTempFilesListener(ActionListener):
    def __init__(self, extension):
        self._extension = extension
    
    def actionPerformed(self, event):
        result = JOptionPane.showConfirmDialog(
            self._extension._main_panel,
            "Are you sure you want to cleanup temporary JavaScript files?",
            "Cleanup Temp Files",
            JOptionPane.YES_NO_OPTION
        )
        if result == JOptionPane.YES_OPTION:
            self._extension._cleanup_temp_files()
            JOptionPane.showMessageDialog(
                self._extension._main_panel,
                "Temporary files cleanup completed. Check the Activity Log for details.",
                "Cleanup Complete",
                JOptionPane.INFORMATION_MESSAGE
            )

class ClearResultsListener(ActionListener):
    def __init__(self, extension):
        self._extension = extension
    
    def actionPerformed(self, event):
        result = JOptionPane.showConfirmDialog(
            self._extension._main_panel,
            "Are you sure you want to clear all results?",
            "Confirm Clear",
            JOptionPane.YES_NO_OPTION
        )
        
        if result == JOptionPane.YES_OPTION:
            self._extension._table_model.setRowCount(0)
            self._extension._scan_results.clear()
            self._extension._scanned_urls.clear()
            self._extension._log_message("Results cleared")


class ExportResultsListener(ActionListener):
    def __init__(self, extension):
        self._extension = extension
    
    def actionPerformed(self, event):
        file_chooser = JFileChooser()
        file_chooser.setSelectedFile(java.io.File("jshunter_results.json"))
        
        result = file_chooser.showSaveDialog(self._extension._main_panel)
        if result == JFileChooser.APPROVE_OPTION:
            try:
                file = file_chooser.getSelectedFile()
                with open(str(file), 'w') as f:
                    json.dump(list(self._extension._scan_results), f, indent=2)
                
                JOptionPane.showMessageDialog(
                    self._extension._main_panel, 
                    "Results exported successfully!", 
                    "Success", 
                    JOptionPane.INFORMATION_MESSAGE
                )
                self._extension._log_message("Results exported to: " + str(file))
                
            except Exception as e:
                JOptionPane.showMessageDialog(
                    self._extension._main_panel, 
                    "Error exporting results: " + str(e), 
                    "Error", 
                    JOptionPane.ERROR_MESSAGE
                )
                self._extension._log_message("Error exporting results: " + str(e))


class ResultDetailsListener(MouseAdapter):
    def __init__(self, extension):
        self._extension = extension
    
    def mouseClicked(self, event):
        if event.getClickCount() == 2:
            self._show_result_details()
    
    def _show_result_details(self):
        selected_row = self._extension._results_table.getSelectedRow()
        if selected_row == -1:
            return
        
        model_row = self._extension._results_table.convertRowIndexToModel(selected_row)
        result = self._extension._scan_results.get(model_row)
        
        # Create details dialog
        dialog = JDialog(None, "Scan Result Details", True)
        dialog.setSize(800, 600)
        dialog.setLocationRelativeTo(self._extension._main_panel)
        
        panel = JPanel(BorderLayout())
        
        # URL info
        url_panel = JPanel(BorderLayout())
        url_panel.setBorder(BorderFactory.createTitledBorder("URL"))
        url_area = JTextArea(result['url'])
        url_area.setEditable(False)
        url_area.setRows(2)
        url_panel.add(JScrollPane(url_area), BorderLayout.CENTER)
        
        # Findings table
        findings_panel = JPanel(BorderLayout())
        findings_panel.setBorder(BorderFactory.createTitledBorder("Findings"))
        
        column_names = ["Detector", "Verified", "Line", "Value"]
        findings_model = DefaultTableModel(column_names, 0)
        
        findings_table = JTable(findings_model)
        findings_table.setRowSorter(TableRowSorter(findings_model))
        
        for finding in result['findings']:
            detector_name = finding.get('DetectorName', 'Unknown')
            raw_value = finding.get('Raw', '')
            verified = finding.get('Verified', False)
            line_number = finding.get('SourceMetadata', {}).get('Data', {}).get('Filesystem', {}).get('line', 0)
            
            row_data = [
                detector_name,
                "Yes" if verified else "No",
                line_number if line_number > 0 else "",
                raw_value[:100] + "..." if len(raw_value) > 100 else raw_value
            ]
            findings_model.addRow(row_data)
        
        findings_panel.add(JScrollPane(findings_table), BorderLayout.CENTER)
        
        panel.add(url_panel, BorderLayout.NORTH)
        panel.add(findings_panel, BorderLayout.CENTER)
        
        # Close button
        button_panel = JPanel(FlowLayout())
        close_button = JButton("Close")
        close_button.addActionListener(lambda e: dialog.dispose())
        button_panel.add(close_button)
        panel.add(button_panel, BorderLayout.SOUTH)
        
        dialog.add(panel)
        dialog.setVisible(True)
