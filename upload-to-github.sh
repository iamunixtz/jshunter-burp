#!/bin/bash

# Upload files to GitHub repository using GitHub API
# This script uploads files directly to the GitHub repository

echo "🚀 Uploading JSHunter Burp Suite Extension to GitHub"
echo "=================================================="

# Get GitHub token from gh CLI
TOKEN=$(gh auth token 2>/dev/null)

if [ -z "$TOKEN" ]; then
    echo "❌ Error: GitHub token not found. Please run 'gh auth login' first."
    exit 1
fi

REPO="iamunixtz/jshunter-burp"
BASE_URL="https://api.github.com/repos/$REPO"

echo "📋 Repository: $REPO"
echo "🔑 Token: ${TOKEN:0:10}..."

# Function to upload a file
upload_file() {
    local file_path="$1"
    local file_name=$(basename "$file_path")
    local content=$(base64 -w 0 "$file_path")
    
    echo "📤 Uploading: $file_name"
    
    # Check if file exists
    local sha=$(curl -s -H "Authorization: token $TOKEN" \
        -H "Accept: application/vnd.github.v3+json" \
        "$BASE_URL/contents/$file_name" | jq -r '.sha // empty')
    
    if [ -n "$sha" ]; then
        echo "  ⚠️  File exists, updating..."
        local method="PUT"
    else
        echo "  ➕ Creating new file..."
        local method="PUT"
    fi
    
    # Upload/update file
    local response=$(curl -s -X $method \
        -H "Authorization: token $TOKEN" \
        -H "Accept: application/vnd.github.v3+json" \
        -H "Content-Type: application/json" \
        "$BASE_URL/contents/$file_name" \
        -d "{
            \"message\": \"Add $file_name\",
            \"content\": \"$content\",
            \"sha\": \"$sha\"
        }")
    
    local status=$(echo "$response" | jq -r '.content.download_url // empty')
    
    if [ -n "$status" ]; then
        echo "  ✅ Success: $file_name uploaded"
    else
        echo "  ❌ Error uploading $file_name"
        echo "  Response: $response"
    fi
}

# Upload all files
echo ""
echo "📁 Uploading files..."

for file in *.py *.md *.txt *.sh; do
    if [ -f "$file" ]; then
        upload_file "$file"
    fi
done

echo ""
echo "✅ Upload complete!"
echo "🌐 Repository: https://github.com/$REPO"
echo ""
echo "📖 Next steps:"
echo "  1. Visit https://github.com/$REPO"
echo "  2. Download jshunter_extension.py"
echo "  3. Install in Burp Suite"
echo "  4. Configure TruffleHog and Discord webhook"
