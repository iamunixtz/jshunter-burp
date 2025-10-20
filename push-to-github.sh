#!/bin/bash

# JSHunter Burp Suite Extension - Push to GitHub
# This script helps push the repository to GitHub

echo "🚀 JSHunter Burp Suite Extension - GitHub Push Helper"
echo "=================================================="
echo ""

echo "📋 Repository Information:"
echo "  - Repository: https://github.com/iamunixtz/jshunter-burp"
echo "  - Local Path: $(pwd)"
echo ""

echo "📁 Files ready to push:"
ls -la
echo ""

echo "🔧 To push to GitHub, run one of these commands:"
echo ""
echo "Option 1 - Using GitHub CLI (if authenticated):"
echo "  gh auth login"
echo "  git push -u origin main"
echo ""
echo "Option 2 - Using Personal Access Token:"
echo "  git push https://YOUR_TOKEN@github.com/iamunixtz/jshunter-burp.git main"
echo ""
echo "Option 3 - Manual upload via GitHub web interface:"
echo "  1. Go to https://github.com/iamunixtz/jshunter-burp"
echo "  2. Click 'uploading an existing file'"
echo "  3. Drag and drop all files"
echo "  4. Commit with message: 'Initial release: JSHunter Burp Suite Extension v1.0.0'"
echo ""

echo "✅ Repository is ready for GitHub!"
echo "📖 Check README.md for installation instructions"
echo "🔧 Check INSTALLATION.md for detailed setup guide"
