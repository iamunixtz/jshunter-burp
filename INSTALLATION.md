# JSHunter Burp Suite Extension - Installation Guide

## Quick Installation

1. **Download the Extension**: Get `jshunter_extension.py` from this repository
2. **Open Burp Suite**: Launch Burp Suite Professional or Community
3. **Go to Extensions**: Navigate to **Extensions** → **Extensions**
4. **Add Extension**: Click **Add** → **Extension type: Python**
5. **Select File**: Choose `jshunter_extension.py`
6. **Install**: Click **Next** and the extension will be loaded

## Prerequisites

### Burp Suite
- **Burp Suite Professional** (recommended) or **Burp Suite Community**
- Python support enabled (comes with Jython)

### TruffleHog Installation

**macOS:**
```bash
brew install trufflehog
```

**Linux:**
```bash
# Download the latest release
curl -L https://github.com/trufflesecurity/trufflehog/releases/latest/download/trufflehog_3.63.7_linux_amd64.tar.gz | tar -xz
sudo mv trufflehog /usr/local/bin/
```

**Windows:**
```bash
# Using Chocolatey
choco install trufflehog

# Or download from GitHub releases
```

### Discord Webhook Setup

1. Go to your Discord server
2. Right-click on the channel where you want notifications
3. Select **Edit Channel**
4. Go to **Integrations** → **Webhooks**
5. Click **Create Webhook**
6. Copy the webhook URL

## Step-by-Step Installation

### Step 1: Download the Extension
```bash
# Clone the repository
git clone https://github.com/yourusername/jshunter-burp.git
cd jshunter-burp

# Or download just the extension file
wget https://raw.githubusercontent.com/yourusername/jshunter-burp/main/jshunter_extension.py
```

### Step 2: Install in Burp Suite

1. **Open Burp Suite**
2. **Navigate to Extensions**:
   - Go to **Extensions** tab
   - Click **Extensions** in the left sidebar
3. **Add New Extension**:
   - Click **Add** button
   - Select **Extension type: Python**
4. **Select Extension File**:
   - Click **Select file...**
   - Navigate to and select `jshunter_extension.py`
5. **Load Extension**:
   - Click **Next**
   - The extension should load successfully
   - You should see "JSHunter" tab appear in the interface

### Step 3: Configure the Extension

1. **Open JSHunter Tab**: Click on the "JSHunter" tab
2. **Set TruffleHog Path**: 
   - Enter the path to your TruffleHog binary
   - Default: `/usr/local/bin/trufflehog`
   - Use the "Browse" button to find the file
3. **Test TruffleHog**: Click "Test" button to verify TruffleHog is working
4. **Set Discord Webhook**: Enter your Discord webhook URL
5. **Test Discord**: Click "Test Discord" button to verify webhook
6. **Save Settings**: Click "Save Settings" button

## Configuration Options

| Setting | Description | Default |
|---------|-------------|---------|
| TruffleHog Path | Path to TruffleHog executable | `/usr/local/bin/trufflehog` |
| Discord Webhook URL | Discord webhook for notifications | Empty |
| Auto-scan JavaScript URLs | Automatically scan detected JS files | Enabled |
| Send Findings to Discord | Send findings to Discord webhook | Enabled |

## Usage

1. **Start Monitoring**: The extension automatically monitors HTTP traffic when enabled
2. **Browse Websites**: Navigate to websites with JavaScript files
3. **View Results**: Scan results appear in the JSHunter interface
4. **Review Findings**: Click on findings to see details
5. **Discord Notifications**: Verified and unverified secrets are sent to Discord

## Troubleshooting

### Extension Not Loading
- **Check File Path**: Ensure the path to `jshunter_extension.py` is correct
- **Python Type**: Make sure you selected "Python" as the extension type
- **File Permissions**: Ensure Burp Suite can read the file
- **Error Logs**: Check the "Errors" tab in Extensions for error messages

### TruffleHog Not Found
- **Verify Installation**: Run `trufflehog --version` in terminal
- **Check Path**: Ensure the path in settings is correct
- **Test Button**: Use the "Test TruffleHog" button to verify
- **Permissions**: Ensure TruffleHog binary is executable

### Discord Webhook Not Working
- **Verify URL**: Check that the webhook URL is correct
- **Test Button**: Use the "Test Discord" button to verify
- **Server Permissions**: Ensure the webhook has permission to send messages
- **Channel Access**: Verify the webhook is in the correct channel

### No JavaScript URLs Detected
- **Auto-scan Enabled**: Check that auto-scanning is enabled in settings
- **HTTP Traffic**: Ensure you're browsing websites with JavaScript files
- **File Extensions**: Look for `.js` files in HTTP traffic
- **Proxy Settings**: Verify Burp Suite proxy is configured correctly

### Performance Issues
- **Large Files**: Very large JavaScript files may take time to scan
- **Multiple Scans**: Avoid scanning the same URL multiple times
- **TruffleHog Timeout**: The extension has a 60-second timeout for TruffleHog
- **Memory Usage**: Large numbers of findings may impact performance

## Advanced Configuration

### Custom TruffleHog Options
The extension uses the following TruffleHog command:
```bash
trufflehog filesystem "/path/to/file" --json
```

### Discord Message Format
The extension sends formatted messages to Discord:
- **Verified Secrets**: Marked with `[VERIFIED]`
- **Unverified Secrets**: Marked with `[UNVERIFIED]`
- **Secret Redaction**: Sensitive values are redacted in messages
- **Line Numbers**: Shows the line where the secret was found

### File Cleanup
- Temporary JavaScript files are automatically deleted after scanning
- Cleanup runs on extension startup and when clicking "Cleanup Temp Files"
- Files are stored in the system's temporary directory

## Support

- **Issues**: [GitHub Issues](https://github.com/yourusername/jshunter-burp/issues)
- **Documentation**: [Burp Suite Extensions](https://portswigger.net/burp/documentation/desktop/extensions)
- **TruffleHog**: [TruffleHog Documentation](https://docs.trufflesecurity.com/)

## Uninstallation

1. **Open Burp Suite**
2. **Go to Extensions** → **Extensions**
3. **Find JSHunter**: Look for the JSHunter extension in the list
4. **Remove Extension**: Click **Remove** button
5. **Restart Burp Suite**: Restart to complete removal
