#!/bin/bash

# swtpm Upgrade Script for Keylime
# This script upgrades swtpm to a newer version to fix the 80-attestation limit

set -e

echo "=== swtpm Upgrade Script ==="
echo "Current swtpm version: $(swtpm --version)"
echo

# Check if we're on Ubuntu 22.04
if [[ "$(lsb_release -rs)" != "22.04" ]]; then
    echo "❌ This script is designed for Ubuntu 22.04. Please adapt for your system."
    exit 1
fi

# Method 1: Try to get newer version from Ubuntu repos
echo "🔍 Checking for newer swtpm versions..."
apt update

# Check what's available
echo "Available swtpm packages:"
apt list -a swtpm swtpm-tools libtpms0 2>/dev/null | grep -v WARNING

echo
echo "Choose upgrade method:"
echo "1. Try Ubuntu backports (safest)"
echo "2. Build from source (latest features)"
echo "3. Skip upgrade and use workaround only"
read -p "Enter choice (1-3): " choice

case $choice in
    1)
        echo "🔧 Attempting to enable Ubuntu backports..."
        # Add backports repo
        echo "deb http://archive.ubuntu.com/ubuntu jammy-backports main universe" | sudo tee /etc/apt/sources.list.d/backports.list
        apt update
        
        # Try to install newer version
        echo "🔄 Attempting to upgrade swtpm..."
        apt install -t jammy-backports swtpm swtpm-tools libtpms0 || {
            echo "⚠️  Backports upgrade failed. Continuing with workaround."
        }
        ;;
    2)
        echo "🔧 Building swtpm from source..."
        
        # Install build dependencies
        apt install -y build-essential autoconf automake libtool pkg-config \
            libglib2.0-dev libgnutls28-dev libjson-glib-dev \
            libtpms-dev libseccomp-dev
        
        # Create build directory
        mkdir -p /tmp/swtpm-build
        cd /tmp/swtpm-build
        
        # Download and build swtpm
        echo "📥 Downloading swtpm source..."
        wget https://github.com/stefanberger/swtpm/archive/refs/tags/v0.8.0.tar.gz
        tar -xzf v0.8.0.tar.gz
        cd swtpm-0.8.0
        
        echo "🔨 Building swtpm..."
        ./autogen.sh
        ./configure --prefix=/usr/local
        make -j$(nproc)
        
        # Stop services before upgrade
        echo "⏹️  Stopping Keylime services..."
        cd /home/shubhgupta/keylime
        docker-compose down || docker compose down || true
        
        # Install new version
        echo "📦 Installing new swtpm..."
        make install
        
        # Update library cache
        ldconfig
        
        echo "✅ swtpm built and installed from source"
        ;;
    3)
        echo "⏭️  Skipping upgrade, using workaround only"
        ;;
    *)
        echo "❌ Invalid choice"
        exit 1
        ;;
esac

echo
echo "=== Post-upgrade Status ==="
echo "swtpm version: $(swtpm --version)"
echo

# Test the installation
echo "🧪 Testing swtpm installation..."
swtpm --help > /dev/null && echo "✅ swtpm is working" || echo "❌ swtpm test failed"

echo
echo "=== Next Steps ==="
echo "1. Clear existing TPM state: rm -rf /home/shubhgupta/tpm_state/*"
echo "2. Restart Keylime services: cd /home/shubhgupta/keylime && docker-compose up -d"
echo "3. Use the enhanced monitor script with automatic TPM reset"
echo "4. Monitor attestation count - should now exceed 80"
echo
echo "🔧 Enhanced monitor script features:"
echo "   - Proactive TPM reset at 75 attestations"
echo "   - Manual TPM reset: ./final_monitor.sh reset-tpm"
echo "   - Continuous monitoring handles the limitation automatically"
