# JSHunter Burp Suite Extension - Release Notes

## Version 1.0.0 - Initial Release

### 🎉 What's New

**Core Features:**
- ✅ **Automatic JavaScript URL Detection**: Monitors HTTP traffic and automatically identifies JavaScript files
- ✅ **TruffleHog Integration**: Scans JavaScript files for secrets using the powerful TruffleHog tool
- ✅ **Discord Webhook Support**: Sends findings directly to Discord channels for real-time notifications
- ✅ **Live Results Display**: Shows scan results and findings in a clean, organized interface

**UI Features:**
- ✅ **Resizable Panels**: Adjustable panel sizes for better workflow
- ✅ **Comprehensive Settings**: Configure TruffleHog path, Discord webhook, and scanning behavior
- ✅ **Findings Table**: Detailed view of detected secrets with type, URL, line number, and verification status
- ✅ **Statistics Dashboard**: Shows total findings, verified secrets, and scanned URLs

**Technical Features:**
- ✅ **Persistent Settings**: Settings are saved across Burp Suite sessions
- ✅ **Automatic Cleanup**: Temporary files are automatically cleaned up after scanning
- ✅ **Error Handling**: Comprehensive error handling and user feedback
- ✅ **File Browser**: Easy TruffleHog binary path selection
- ✅ **Test Functions**: Test TruffleHog and Discord webhook configurations

### 🔧 Installation

1. **Download**: Get `jshunter_extension.py` from the repository
2. **Install in Burp Suite**: 
   - Go to **Extensions** → **Extensions**
   - Click **Add** → **Extension type: Python**
   - Select `jshunter_extension.py`
3. **Configure**: Set TruffleHog path and Discord webhook URL
4. **Start Scanning**: The extension automatically monitors HTTP traffic

### 📋 Requirements

- **Burp Suite**: Professional or Community Edition
- **Python**: Python 2.7 (comes with Burp Suite's Jython)
- **TruffleHog**: TruffleHog binary installed and accessible

### 🚀 Usage

1. **Automatic Monitoring**: The extension automatically detects JavaScript URLs in HTTP traffic
2. **Real-time Scanning**: Downloads and scans JavaScript files using TruffleHog
3. **Discord Notifications**: Sends formatted alerts to Discord webhooks
4. **Results Display**: View detailed findings in the JSHunter interface

### 🎯 Supported Secret Types

- **API Keys**: Various API key patterns
- **Tokens**: Authentication tokens and bearer tokens
- **Passwords**: Password and secret patterns
- **Private Keys**: RSA and SSH private keys
- **And more**: All patterns supported by TruffleHog

### 🔍 Discord Integration

The extension sends formatted messages to Discord:

**Verified Secrets:**
```
**[VERIFIED] Verified Secrets** found in https://example.com/script.js

**GitHub Token**
```
ghp_***REDACTED***
```
Line: 42
```

**Unverified Secrets:**
```
**[UNVERIFIED] Unverified Secrets** found in https://example.com/script.js

**API Key**
```
api_key: "***REDACTED***"
```
Line: 15
```

### 🛠️ Technical Details

- **Language**: Python 2.7 (Jython)
- **UI Framework**: Java Swing
- **HTTP Monitoring**: Burp Suite IHttpListener
- **Secret Scanning**: TruffleHog binary integration
- **Discord Integration**: HTTP POST requests to webhooks
- **File Management**: Automatic temporary file cleanup

### 📁 Repository Structure

```
jshunter-burp/
├── jshunter_extension.py    # Main extension file
├── README.md               # Comprehensive documentation
├── INSTALLATION.md         # Detailed installation guide
├── LICENSE                 # MIT License
├── .gitignore             # Git ignore rules
└── push-to-github.sh      # GitHub push helper script
```

### 🎉 What's Next

Future versions may include:
- Enhanced secret detection patterns
- Custom regex pattern support
- Integration with other security tools
- Advanced filtering options
- Performance optimizations

### 📞 Support

- **Issues**: [GitHub Issues](https://github.com/iamunixtz/jshunter-burp/issues)
- **Documentation**: [README.md](README.md)
- **Installation**: [INSTALLATION.md](INSTALLATION.md)

---

**Happy Hunting! 🎯**
