# app.py - Complete Flask Backend for Phishing Analysis Tool

from flask import Flask, request, jsonify, render_template_string
from flask_cors import CORS
import re
import os
import mimetypes
from urllib.parse import urlparse
import base64
from datetime import datetime

app = Flask(__name__)
CORS(app)  # Enable CORS for frontend requests

# ============= HELPER FUNCTIONS =============

def analyze_url(url):
    """Heuristic-based URL phishing detection"""
    if not url or url.strip() == '':
        return {'verdict': 'info', 'score': 0, 'message': 'Please provide a valid URL.'}
    
    u = url.strip().lower()
    score = 0
    findings = []
    
    # 1. Check for suspicious keywords
    suspicious_keywords = ['login', 'verify', 'secure', 'update', 'banking', 'confirm', 
                          'account', 'password', 'signin', 'credential', 'validate', 
                          'authenticate', 'billing', 'paypal', 'apple', 'microsoft']
    found_keywords = [kw for kw in suspicious_keywords if kw in u]
    if found_keywords:
        score += len(found_keywords) * 1.5
        findings.append(f"Suspicious keywords: {', '.join(found_keywords[:4])}")
    
    # 2. Check for IP address instead of domain
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    if re.search(ip_pattern, u):
        score += 4
        findings.append("IP address used instead of domain name")
    
    # 3. Check for URL shorteners
    shorteners = ['bit.ly', 'tinyurl', 'shorturl', 'goo.gl', 'ow.ly', 'is.gd', 
                 'buff.ly', 'tiny.cc', 'tr.im', 'v.gd', 'cutt.ly']
    for shortener in shorteners:
        if shortener in u:
            score += 3
            findings.append(f"URL shortener detected: {shortener}")
            break
    
    # 4. Check for HTTPS
    if u.startswith('http://'):
        score += 2
        findings.append("Uses HTTP instead of HTTPS")
    elif not u.startswith('https://') and not u.startswith('http://'):
        findings.append("Missing protocol (assuming HTTP)")
        score += 1
    
    # 5. Check for suspicious TLDs
    suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.top', '.xyz', '.club', 
                      '.online', '.site', '.website', '.space', '.tech', '.info']
    for tld in suspicious_tlds:
        if u.endswith(tld):
            score += 3
            findings.append(f"Suspicious TLD: {tld}")
            break
    
    # 6. Check for excessive subdomains
    subdomain_count = u.count('.')
    if subdomain_count > 3:
        score += 1
        findings.append(f"Excessive subdomains ({subdomain_count})")
    
    # 7. Check for hyphens and obfuscation
    if '--' in u:
        score += 1
        findings.append("Double hyphen detected (obfuscation)")
    if u.count('-') > 3:
        score += 1
        findings.append("Multiple hyphens detected")
    
    # 8. Check URL length (obfuscation)
    if len(u) > 100:
        score += 1
        findings.append("Very long URL (potential obfuscation)")
    
    # 9. Check for @ symbol (phishing redirection)
    if '@' in u:
        score += 3
        findings.append("URL contains @ symbol (redirection technique)")
    
    # 10. Check for common typosquatting
    typosquatting_patterns = ['rnicrosoft', 'googIe', 'faceb00k', 'amaz0n', 
                             'paypaI', 'appIe', 'micros0ft']
    for pattern in typosquatting_patterns:
        if pattern in u:
            score += 4
            findings.append(f"Typosquatting detected: {pattern}")
            break
    
    # Determine verdict
    if score >= 10:
        verdict = 'phishing'
        message = f"🚨 PHISHING DETECTED (score: {score:.1f}) - Multiple red flags detected. Do not interact with this URL."
    elif score >= 5:
        verdict = 'suspicious'
        message = f"⚠️ SUSPICIOUS (score: {score:.1f}) - Proceed with caution. Consider verifying the source."
    else:
        verdict = 'safe'
        message = f"✅ SAFE (score: {score:.1f}) - No significant phishing indicators detected. Stay vigilant."
    
    # Add findings to message if any
    if findings:
        message += f"\n\n📋 Details: " + "\n• ".join([""] + findings)
    
    return {
        'verdict': verdict,
        'score': round(score, 1),
        'message': message,
        'findings': findings,
        'url': url
    }


def analyze_file(file_data):
    """Heuristic-based file phishing detection"""
    if not file_data:
        return {'verdict': 'info', 'score': 0, 'message': 'No file provided.'}
    
    filename = file_data.get('filename', 'unknown')
    file_content = file_data.get('content', '')
    file_size = file_data.get('size', 0)
    
    name_lower = filename.lower()
    score = 0
    findings = []
    
    # 1. Check dangerous extensions
    dangerous_ext = ['.exe', '.scr', '.bat', '.cmd', '.ps1', '.js', '.jar', 
                    '.app', '.dmg', '.vbs', '.msi', '.com', '.pif', '.cpl']
    for ext in dangerous_ext:
        if name_lower.endswith(ext):
            score += 5
            findings.append(f"Dangerous extension: {ext}")
            break
    
    # 2. Check suspicious extensions
    suspicious_ext = ['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', 
                     '.zip', '.rar', '.7z', '.iso', '.img']
    for ext in suspicious_ext:
        if name_lower.endswith(ext):
            score += 2
            findings.append(f"Suspicious extension: {ext}")
            break
    
    # 3. Check for double extension (e.g., invoice.pdf.exe)
    if name_lower.count('.') > 1:
        score += 4
        findings.append("Double extension detected (potential obfuscation)")
    
    # 4. Check for suspicious keywords in filename
    suspicious_words = ['invoice', 'payment', 'urgent', 'confirm', 'update', 
                       'password', 'document', 'scan', 'copy', 'bill', 'receipt',
                       'statement', 'tax', 'financial', 'secret', 'confidential']
    found_words = [w for w in suspicious_words if w in name_lower]
    if found_words:
        score += len(found_words) * 1.5
        findings.append(f"Suspicious keywords: {', '.join(found_words[:3])}")
    
    # 5. Check file size (very small or very large)
    if file_size > 0:
        if file_size < 1024:  # Less than 1KB
            score += 1
            findings.append("Very small file size (< 1KB)")
        elif file_size > 10 * 1024 * 1024:  # Greater than 10MB
            score += 1
            findings.append("Large file size (> 10MB)")
    
    # 6. Check for spaces and special characters in filename
    if ' ' in name_lower:
        score += 1
        findings.append("Spaces in filename")
    if any(c in name_lower for c in ['!', '@', '#', '$', '%', '^', '&', '*']):
        score += 1
        findings.append("Special characters in filename")
    
    # 7. Check for known malicious file names
    malicious_names = ['virus', 'malware', 'trojan', 'ransomware', 'worm', 
                      'keylogger', 'spyware', 'adware', 'rootkit']
    for m_name in malicious_names:
        if m_name in name_lower:
            score += 3
            findings.append(f"Malicious filename pattern: {m_name}")
            break
    
    # 8. Simple content check (if provided as text)
    if file_content and isinstance(file_content, str):
        # Check for suspicious patterns in text content
        suspicious_patterns = ['eval(', 'exec(', 'document.write', 'script>', 
                              'onload=', 'onerror=', 'base64_decode']
        for pattern in suspicious_patterns:
            if pattern in file_content.lower():
                score += 3
                findings.append(f"Suspicious code pattern: {pattern}")
                break
        
        # Check for obfuscation in content
        if len(file_content) > 1000:
            # Check for high density of special characters (potential obfuscation)
            special_count = sum(1 for c in file_content if not c.isalnum() and not c.isspace())
            if special_count / len(file_content) > 0.3:
                score += 2
                findings.append("High density of special characters (possible obfuscation)")
    
    # Determine verdict
    if score >= 10:
        verdict = 'phishing'
        message = f"🚨 FILE PHISHING DETECTED (score: {score:.1f}) - High-risk file detected. Do not open."
    elif score >= 5:
        verdict = 'suspicious'
        message = f"⚠️ FILE SUSPICIOUS (score: {score:.1f}) - Exercise caution when opening this file."
    else:
        verdict = 'safe'
        message = f"✅ FILE SAFE (score: {score:.1f}) - No significant threats detected."
    
    if findings:
        message += f"\n\n📋 Details: " + "\n• ".join([""] + findings)
    
    return {
        'verdict': verdict,
        'score': round(score, 1),
        'message': message,
        'findings': findings,
        'filename': filename
    }


# ============= API ENDPOINTS =============

@app.route('/')
def index():
    """Serve the frontend HTML"""
    return render_template_string(HTML_TEMPLATE)


@app.route('/api/analyze-link', methods=['POST'])
def analyze_link_endpoint():
    """API endpoint for link analysis"""
    data = request.get_json()
    url = data.get('url', '')
    result = analyze_url(url)
    return jsonify(result)


@app.route('/api/analyze-file', methods=['POST'])
def analyze_file_endpoint():
    """API endpoint for file analysis"""
    # Check if file was uploaded
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    # Read file content (up to 1MB for text analysis)
    file_content = None
    try:
        # Try to read as text (up to 1MB)
        file.seek(0)
        content_bytes = file.read(1024 * 1024)
        file_content = content_bytes.decode('utf-8', errors='ignore')
    except Exception:
        file_content = None
    
    # Prepare file data for analysis
    file_data = {
        'filename': file.filename,
        'content': file_content,
        'size': len(content_bytes) if content_bytes else 0
    }
    
    result = analyze_file(file_data)
    return jsonify(result)


# ============= HTML TEMPLATE =============

HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Phishing Analyzer · Link & File Scanner</title>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css">
  <style>
    * {
      margin: 0;
      padding: 0;
      box-sizing: border-box;
      font-family: 'Segoe UI', Roboto, system-ui, sans-serif;
    }
    body {
      background: linear-gradient(145deg, #f6f9fc 0%, #e9f0f5 100%);
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 1.5rem;
    }
    .card {
      max-width: 1100px;
      width: 100%;
      background: rgba(255,255,255,0.85);
      backdrop-filter: blur(12px);
      border-radius: 48px;
      box-shadow: 0 25px 50px -10px rgba(0,20,40,0.25);
      padding: 2.5rem 2.8rem;
      border: 1px solid rgba(255,255,255,0.3);
    }
    .header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 1rem;
      margin-bottom: 1.5rem;
    }
    h1 {
      font-weight: 600;
      font-size: 2.2rem;
      color: #0b1e2e;
      display: flex;
      align-items: center;
      gap: 12px;
    }
    h1 i { color: #d73f3f; }
    .status-badge {
      background: #1d3f57;
      color: white;
      padding: 0.4rem 1.2rem;
      border-radius: 40px;
      font-size: 0.8rem;
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .status-badge i { color: #5bc0be; }
    .subhead {
      color: #2c3f4f;
      margin-bottom: 2rem;
      border-left: 4px solid #3b8cbf;
      padding-left: 1rem;
      background: rgba(59, 140, 191, 0.06);
      border-radius: 0 12px 12px 0;
      padding: 0.5rem 1rem;
    }
    .grid-2 {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 2rem;
      margin-bottom: 2rem;
    }
    @media (max-width: 768px) {
      .grid-2 { grid-template-columns: 1fr; }
      .card { padding: 1.5rem; }
    }
    .panel {
      background: white;
      border-radius: 28px;
      padding: 1.6rem 1.8rem;
      box-shadow: 0 8px 20px -8px rgba(0,20,30,0.12);
      border: 1px solid rgba(255,255,255,0.7);
    }
    .panel-title {
      display: flex;
      align-items: center;
      gap: 10px;
      font-weight: 600;
      font-size: 1.2rem;
      color: #1b2f3e;
      margin-bottom: 1.4rem;
      border-bottom: 2px solid #eef4f8;
      padding-bottom: 0.6rem;
    }
    .panel-title i { color: #2a6b8f; width: 1.8rem; }
    .input-group {
      display: flex;
      flex-direction: column;
      gap: 0.7rem;
    }
    .input-group label {
      font-weight: 500;
      font-size: 0.9rem;
      color: #1f3a4b;
      display: flex;
      align-items: center;
      gap: 6px;
    }
    .input-group input, .input-group textarea {
      padding: 0.9rem 1.2rem;
      border-radius: 40px;
      border: 1.5px solid #dde7ed;
      background: #fafdff;
      font-size: 0.95rem;
      transition: 0.2s;
      outline: none;
    }
    .input-group input:focus, .input-group textarea:focus {
      border-color: #3b8cbf;
      box-shadow: 0 0 0 4px rgba(59, 140, 191, 0.15);
      background: white;
    }
    .file-upload-wrapper {
      position: relative;
      margin-top: 0.4rem;
    }
    .file-upload-wrapper input[type="file"] {
      position: absolute;
      left: 0;
      top: 0;
      opacity: 0;
      width: 100%;
      height: 100%;
      cursor: pointer;
    }
    .file-upload-label {
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 10px;
      background: #ecf3f8;
      border-radius: 60px;
      padding: 0.9rem 1.2rem;
      border: 1.5px dashed #849aa8;
      color: #1e3b4e;
      font-weight: 500;
      transition: 0.2s;
    }
    .file-upload-label:hover {
      background: #e1ecf5;
      border-color: #3b8cbf;
    }
    .btn {
      background: #1d3f57;
      border: none;
      color: white;
      font-weight: 600;
      padding: 0.9rem 1.8rem;
      border-radius: 60px;
      font-size: 1rem;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 10px;
      cursor: pointer;
      transition: 0.15s;
      box-shadow: 0 6px 14px rgba(26, 67, 95, 0.25);
      margin-top: 1.2rem;
      width: 100%;
    }
    .btn:hover {
      background: #143141;
      transform: scale(0.98);
    }
    .btn-secondary {
      background: #e4edf4;
      color: #1b3850;
      box-shadow: none;
      border: 1px solid #cbdae5;
    }
    .btn-secondary:hover { background: #d3e0ea; }
    .result-area {
      background: #f0f6fc;
      border-radius: 28px;
      padding: 1.6rem 1.8rem;
      border: 1px solid rgba(255,255,255,0.6);
    }
    .result-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      font-weight: 500;
      color: #1b3a4e;
    }
    .result-header i { font-size: 1.2rem; color: #236783; }
    #analysisOutput {
      background: white;
      border-radius: 20px;
      padding: 1.2rem 1.5rem;
      margin-top: 0.8rem;
      min-height: 100px;
      border: 1px solid #d9e5ef;
      white-space: pre-wrap;
      word-break: break-word;
      font-size: 0.95rem;
      line-height: 1.6;
      color: #132b3b;
    }
    .loader {
      display: inline-block;
      width: 20px;
      height: 20px;
      border: 3px solid #eef4f8;
      border-radius: 50%;
      border-top-color: #1d3f57;
      animation: spin 0.8s linear infinite;
    }
    @keyframes spin { to { transform: rotate(360deg); } }
    .flex-row {
      display: flex;
      gap: 12px;
      flex-wrap: wrap;
      align-items: center;
    }
    .footer-note {
      text-align: center;
      margin-top: 1.8rem;
      font-size: 0.8rem;
      color: #4a6479;
      border-top: 1px solid #d8e3ec;
      padding-top: 1.5rem;
    }
    .footer-note i { color: #b13e3e; }
    .file-name-display {
      background: #eef4f8;
      padding: 0.2rem 1rem;
      border-radius: 30px;
      font-size: 0.85rem;
      color: #17425e;
      display: inline-block;
      max-width: 200px;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }
  </style>
</head>
<body>
<div class="card">
  <div class="header">
    <h1><i class="fas fa-shield-halved"></i> Phishing Analyzer</h1>
    <span class="status-badge"><i class="fas fa-circle"></i> Backend: Python Flask</span>
  </div>
  <div class="subhead">
    <i class="fas fa-robot" style="margin-right: 8px;"></i> Heuristic analysis engine · Link & File scanning
  </div>

  <div class="grid-2">
    <!-- URL Panel -->
    <div class="panel">
      <div class="panel-title"><i class="fas fa-link"></i> Link Scanner</div>
      <div class="input-group">
        <label><i class="fas fa-edit"></i> Enter URL</label>
        <input type="text" id="linkInput" placeholder="https://example.com" value="https://secure-login-update.com">
      </div>
      <button class="btn" id="analyzeLinkBtn"><i class="fas fa-search"></i> Analyze Link</button>
    </div>

    <!-- File Panel -->
    <div class="panel">
      <div class="panel-title"><i class="fas fa-file-circle-check"></i> File Inspector</div>
      <div class="input-group">
        <label><i class="fas fa-cloud-upload-alt"></i> Upload suspicious file</label>
        <div class="file-upload-wrapper">
          <div class="file-upload-label" id="fileUploadLabel">
            <i class="fas fa-folder-open"></i> <span id="fileNameDisplay">Choose file...</span>
          </div>
          <input type="file" id="fileInput">
        </div>
      </div>
      <button class="btn" id="analyzeFileBtn"><i class="fas fa-file-signature"></i> Analyze File</button>
    </div>
  </div>

  <!-- Results -->
  <div class="result-area">
    <div class="result-header">
      <span><i class="fas fa-chart-simple"></i> Analysis Report</span>
      <span><i class="fas fa-circle" style="color: #4f8eb3; font-size: 0.7rem;"></i> Powered by Python</span>
    </div>
    <div id="analysisOutput">
      <span style="color: #4e6f85;"><i class="fas fa-hourglass-half"></i> Waiting for input...</span>
    </div>
    <button class="btn btn-secondary" id="clearBtn" style="margin-top: 0.8rem; width: auto; padding: 0.4rem 1.8rem; float: right;">
      <i class="fas fa-eraser"></i> Clear
    </button>
  </div>
  <div class="footer-note">
    <i class="fas fa-server"></i> Backend API · 
    <i class="fas fa-code"></i> Flask + Python · 
    <i class="fas fa-shield-alt"></i> Heuristic detection
  </div>
</div>

<script>
  (function() {
    "use strict";

    const linkInput = document.getElementById('linkInput');
    const analyzeLinkBtn = document.getElementById('analyzeLinkBtn');
    const fileInput = document.getElementById('fileInput');
    const fileNameDisplay = document.getElementById('fileNameDisplay');
    const analyzeFileBtn = document.getElementById('analyzeFileBtn');
    const output = document.getElementById('analysisOutput');
    const clearBtn = document.getElementById('clearBtn');

    function setOutput(text, type = 'info') {
      let icon = 'fa-circle-info';
      let color = '#1d4a6b';
      if (type === 'safe') { icon = 'fa-circle-check'; color = '#1f8b4c'; }
      else if (type === 'phishing') { icon = 'fa-circle-exclamation'; color = '#c73d3d'; }
      else if (type === 'suspicious') { icon = 'fa-triangle-exclamation'; color = '#b16f2a'; }
      output.innerHTML = `<i class="fas ${icon}" style="color:${color}; margin-right: 10px;"></i>${text}`;
    }

    function showLoading() {
      output.innerHTML = `<div class="loader"></div> Analyzing...`;
    }

    // ----- API Calls -----
    async function analyzeLink(url) {
      showLoading();
      try {
        const response = await fetch('/api/analyze-link', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url: url })
        });
        const data = await response.json();
        setOutput(data.message, data.verdict);
      } catch (error) {
        setOutput('❌ Error connecting to backend. Make sure the server is running.', 'info');
        console.error('Error:', error);
      }
    }

    async function analyzeFile(file) {
      showLoading();
      const formData = new FormData();
      formData.append('file', file);
      
      try {
        const response = await fetch('/api/analyze-file', {
          method: 'POST',
          body: formData
        });
        const data = await response.json();
        if (data.error) {
          setOutput('❌ ' + data.error, 'info');
        } else {
          setOutput(data.message, data.verdict);
        }
      } catch (error) {
        setOutput('❌ Error connecting to backend. Make sure the server is running.', 'info');
        console.error('Error:', error);
      }
    }

    // ----- Event Handlers -----
    function handleLinkAnalysis() {
      const url = linkInput.value.trim();
      if (!url) {
        setOutput('⚠️ Please enter a URL to analyze.', 'info');
        return;
      }
      analyzeLink(url);
    }

    function handleFileAnalysis() {
      const file = fileInput.files[0];
      if (!file) {
        setOutput('⚠️ Please select a file to analyze.', 'info');
        return;
      }
      analyzeFile(file);
    }

    // File input display
    fileInput.addEventListener('change', function() {
      if (this.files && this.files[0]) {
        fileNameDisplay.textContent = this.files[0].name;
      } else {
        fileNameDisplay.textContent = 'Choose file...';
      }
    });

    // Clear
    clearBtn.addEventListener('click', function() {
      setOutput('🔄 Ready for next analysis', 'info');
      linkInput.value = '';
      fileInput.value = '';
      fileNameDisplay.textContent = 'Choose file...';
    });

    // Button events
    analyzeLinkBtn.addEventListener('click', handleLinkAnalysis);
    analyzeFileBtn.addEventListener('click', handleFileAnalysis);

    // Enter key for link
    linkInput.addEventListener('keypress', function(e) {
      if (e.key === 'Enter') {
        e.preventDefault();
        handleLinkAnalysis();
      }
    });

    // Auto-analyze on load (demo)
    window.addEventListener('DOMContentLoaded', function() {
      setTimeout(() => {
        analyzeLink('https://secure-login-update.com');
      }, 300);
    });

  })();
</script>
</body>
</html>
'''

# ============= RUN THE APP =============

if __name__ == '__main__':
    print("""
    ╔══════════════════════════════════════════════════════╗
    ║       🛡️  PHISHING ANALYZER · BACKEND RUNNING      ║
    ╠══════════════════════════════════════════════════════╣
    ║  Server: http://127.0.0.1:5000                      ║
    ║  API:    /api/analyze-link  (POST)                 ║
    ║         /api/analyze-file  (POST)                  ║
    ╚══════════════════════════════════════════════════════╝
    """)
    app.run(debug=True, host='0.0.0.0', port=5000)
