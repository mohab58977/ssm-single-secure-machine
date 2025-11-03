#!/bin/bash

# Helper script to prepare logo.png for deployment

echo "======================================"
echo "Logo Preparation Script"
echo "======================================"
echo ""

# Check if logo.png already exists
if [ -f "logo.png" ] && file logo.png | grep -q "PNG image"; then
    echo "✅ logo.png already exists and is a valid PNG"
    ls -lh logo.png
    echo ""
    read -p "Replace it? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Keeping existing logo.png"
        exit 0
    fi
fi

echo "Please provide the path to your image file:"
echo "Examples:"
echo "  ~/Desktop/myimage.png"
echo "  /Users/mohabhassan/Pictures/logo.jpg"
echo ""
read -p "Image path: " IMAGE_PATH

# Expand ~ to home directory
IMAGE_PATH="${IMAGE_PATH/#\~/$HOME}"

# Check if file exists
if [ ! -f "$IMAGE_PATH" ]; then
    echo "❌ Error: File not found: $IMAGE_PATH"
    exit 1
fi

# Check file type
FILE_TYPE=$(file -b "$IMAGE_PATH")
echo "File type: $FILE_TYPE"

# Copy the file
echo "Copying to logo.png..."
cp "$IMAGE_PATH" ./logo.png

if [ $? -eq 0 ]; then
    echo "✅ Successfully copied!"
    echo ""
    ls -lh logo.png
    file logo.png
    echo ""
    echo "Next steps:"
    echo "1. git add logo.png"
    echo "2. git commit -m 'Add logo image'"
    echo "3. git push"
    echo "4. Run GitHub Actions workflows"
else
    echo "❌ Error copying file"
    exit 1
fi
