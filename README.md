# 🔐 Phishing Analyzer Tool

## 📋 Project Overview

A powerful **Phishing Detection & Analysis Tool** built with **Python Flask** backend and a responsive frontend interface. This tool uses heuristic analysis to detect suspicious URLs and files, helping users identify potential phishing attempts before they become security threats.

**Live Demo:** [http://127.0.0.1:5000](http://127.0.0.1:5000)

---

## ✨ Features

### 🎯 **Link Analysis**
- **Heuristic-based detection** using 10+ suspicious indicators
- **Real-time scoring system** (0-10+ scale)
- **Detailed findings** with specific red flags
- **Verdict classification**: Safe ⚡ Suspicious ⚠️ Phishing 🚨

### 📁 **File Analysis**
- **Extension-based detection** (dangerous & suspicious extensions)
- **Filename pattern analysis** (double extensions, keywords, typosquatting)
- **Content scanning** for malicious code patterns
- **Size-based risk assessment**

### 🎨 **Modern UI/UX**
- Clean, responsive interface with glass-morphism design
- Real-time analysis with loading indicators
- Visual verdict badges (Safe/Suspicious/Phishing)
- Drag-and-drop file upload support

---

## 🛠️ Technical Architecture

### **Backend (Python Flask)**
```
app.py
├── Flask Application
├── URL Analysis Engine
├── File Analysis Engine
└── REST API Endpoints
```

### **Frontend**
- Vanilla JavaScript with Fetch API
- CSS3 with modern animations
- Font Awesome icons
- No external dependencies

---

## 📊 How It Works

### **URL Analysis Algorithm**

| Indicator | Weight | Example |
|-----------|--------|---------|
| Suspicious Keywords | +1.5 each | "login", "verify", "secure" |
| IP Address Domain | +4 | `http://192.168.1.1` |
| URL Shorteners | +3 | bit.ly, tinyurl |
| HTTP (not HTTPS) | +2 | `http://example.com` |
| Suspicious TLDs | +3 | .tk, .ml, .ga |
| Excessive Subdomains | +1 | `sub.sub.sub.domain.com` |
| Obfuscation (--, @) | +1-3 | `http://site@malicious.com` |
| Typosquatting | +4 | "googIe", "paypaI" |

### **File Analysis Algorithm**

| Indicator | Weight | Example |
|-----------|--------|---------|
| Dangerous Extensions | +5 | .exe, .bat, .js |
| Suspicious Extensions | +2 | .pdf, .zip |
| Double Extension | +4 | `invoice.pdf.exe` |
| Suspicious Keywords | +1.5 each | "invoice", "password" |
| Malicious Filename | +3 | "virus", "malware" |
| Code Patterns | +3 | `eval(`, `document.write` |

---

## 🚀 Installation & Setup

### **Prerequisites**
```bash
Python 3.7+
pip (Python package manager)
```

### **Step-by-Step Installation**

1. **Clone the repository**
```bash
git clone https://github.com/kartikpop02-lab/phishing-analyzer.git
cd phishing-analyzer
```

2. **Create virtual environment (optional)**
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. **Install dependencies**
```bash
pip install flask flask-cors
```

4. **Run the application**
```bash
python app.py
```

5. **Access the tool**
- Open your browser and navigate to: `http://localhost:5000`

---

## 🔌 API Endpoints

### **POST /api/analyze-link**
Analyzes a URL for phishing indicators

**Request Body:**
```json
{
    "url": "https://example.com"
}
```

**Response:**
```json
{
    "verdict": "safe|suspicious|phishing",
    "score": 7.5,
    "message": "Detailed analysis result",
    "findings": ["Suspicious keywords found", "HTTP instead of HTTPS"],
    "url": "https://example.com"
}
```

### **POST /api/analyze-file**
Analyzes a file for phishing/malware indicators

**Request:** Multipart form data with `file` field

**Response:**
```json
{
    "verdict": "safe|suspicious|phishing",
    "score": 8.0,
    "message": "Detailed analysis result",
    "findings": ["Dangerous extension: .exe", "Double extension detected"],
    "filename": "invoice.pdf.exe"
}
```

---

## 📂 Project Structure
```
phishing-analyzer/
├── app.py              # Main Flask application
├── README.md           # Project documentation
  

```

---

## 🧪 Testing Examples

### **Test URLs**
- **Safe:** `https://google.com`
- **Suspicious:** `http://login-secure-update.com`
- **Phishing:** `http://192.168.1.1/secure-login/account/verify`

### **Test Files**
- **Safe:** `document.pdf`
- **Suspicious:** `invoice.pdf.exe`
- **Phishing:** `password_reset.bat`

---

## 🔍 How It Detects Phishing

### **URL Indicators**
1. **Suspicious Keywords**: Searches for common phishing trigger words
2. **IP Addresses**: Detects domains that are actually IP addresses
3. **URL Shorteners**: Identifies known URL shortening services
4. **HTTPS Status**: Checks for missing SSL/TLS encryption
5. **Suspicious TLDs**: Flags uncommon top-level domains
6. **Obfuscation**: Detects characters used to hide malicious intent
7. **Typosquatting**: Catches common misspelling techniques

### **File Indicators**
1. **Dangerous Extensions**: .exe, .bat, .js, etc.
2. **Double Extensions**: `file.pdf.exe` pattern
3. **Malicious Keywords**: "invoice", "payment", "urgent"
4. **Code Patterns**: `eval(`, `document.write`
5. **Size Analysis**: Too small or too large files

---

## 🎯 Use Cases

### **For Individuals**
- Verify suspicious emails before clicking links
- Check downloaded files before opening
- Personal cybersecurity awareness

### **For Organizations**
- Employee security training tool
- Quick file/link verification
- Security awareness demonstrations

### **For Developers**
- Testing phishing detection algorithms
- Understanding heuristic analysis
- Building security tools

---

## 🛡️ Security Considerations

- **No data storage**: All analysis is done in memory
- **File size limit**: 1MB max for text analysis
- **Client-side analysis**: Files stay on your machine
- **Open source**: Fully transparent codebase

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Open a Pull Request

### **Areas for Improvement**
- [ ] Integration with VirusTotal API
- [ ] Machine Learning based detection
- [ ] Browser extension version
- [ ] More advanced file analysis (PE headers, PDF analysis)
- [ ] Real-time URL reputation checking

---

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 📞 Contact & Support

- **GitHub**: [@kartikpop02-lab](https://github.com/kartikpop02-lab)
- **Issues**: [GitHub Issues](https://github.com/kartikpop02-lab/phishing-analyzer/issues)

---

## 🙏 Acknowledgments

- Flask framework for the backend
- Font Awesome for icons
- Open source community for inspiration

---




**⭐ Star this repository if you found it useful!**  
**🔔 Watch for updates and new features!**

---

*Built with ❤️ for cybersecurity awareness*
