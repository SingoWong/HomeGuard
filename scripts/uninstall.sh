#!/bin/bash
#
# HomeGuard Uninstallation Script
#
# This script removes HomeGuard from macOS:
# 1. Stops and removes LaunchDaemon service
# 2. Disables PF firewall rules
# 3. Removes installed files
#
# Usage: sudo ./uninstall.sh [options]
#

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Installation paths
BIN_DIR="/usr/local/bin"
ETC_DIR="/usr/local/etc/homeguard"
VAR_DIR="/var/lib/homeguard"
LOG_DIR="/var/log/homeguard"
LAUNCHD_DIR="/Library/LaunchDaemons"

# File names
BINARY_NAME="homeguard"
PLIST_NAME="com.homeguard.plist"

# PF files
PF_ANCHOR="/etc/pf.anchors/com.homeguard"
PF_CONF_BACKUP="/etc/pf.conf.homeguard.backup"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Helper functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_step() {
    echo -e "${BLUE}[STEP]${NC} $1"
}

# Check root privileges
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (sudo)"
        exit 1
    fi
}

# Stop and remove LaunchDaemon
remove_launchd() {
    log_step "Removing LaunchDaemon service..."

    local plist_path="${LAUNCHD_DIR}/${PLIST_NAME}"

    # Stop service if running
    if launchctl list 2>/dev/null | grep -q "com.homeguard"; then
        log_info "Stopping HomeGuard service..."
        launchctl stop com.homeguard 2>/dev/null || true
        launchctl unload "${plist_path}" 2>/dev/null || true
        log_info "Service stopped"
    fi

    # Remove plist file
    if [[ -f "${plist_path}" ]]; then
        rm -f "${plist_path}"
        log_info "Removed: ${plist_path}"
    fi
}

# Disable PF rules
disable_pf() {
    log_step "Disabling PF firewall rules..."

    # Use setup-pf.sh if available
    local pf_script="${SCRIPT_DIR}/setup-pf.sh"
    if [[ -x "${pf_script}" ]]; then
        "${pf_script}" --disable
    else
        # Manual cleanup
        # Remove anchor file
        if [[ -f "${PF_ANCHOR}" ]]; then
            rm -f "${PF_ANCHOR}"
            log_info "Removed: ${PF_ANCHOR}"
        fi

        # Restore original pf.conf if backup exists
        if [[ -f "${PF_CONF_BACKUP}" ]]; then
            cp "${PF_CONF_BACKUP}" /etc/pf.conf
            log_info "Restored original PF configuration"
        else
            # Remove HomeGuard lines from pf.conf
            if [[ -f /etc/pf.conf ]]; then
                local temp_file=$(mktemp)
                grep -v -E "(HomeGuard|com.homeguard)" /etc/pf.conf > "$temp_file" 2>/dev/null || true
                mv "$temp_file" /etc/pf.conf
                log_info "Removed HomeGuard rules from PF configuration"
            fi
        fi

        # Reload PF
        pfctl -f /etc/pf.conf 2>/dev/null || true
    fi

    log_info "PF rules disabled"
}

# Remove binary
remove_binary() {
    log_step "Removing binary..."

    local binary_path="${BIN_DIR}/${BINARY_NAME}"

    if [[ -f "${binary_path}" ]]; then
        rm -f "${binary_path}"
        log_info "Removed: ${binary_path}"
    else
        log_info "Binary not found (already removed?)"
    fi
}

# Remove configuration
remove_config() {
    log_step "Removing configuration..."

    if [[ -d "${ETC_DIR}" ]]; then
        rm -rf "${ETC_DIR}"
        log_info "Removed: ${ETC_DIR}"
    else
        log_info "Configuration directory not found (already removed?)"
    fi
}

# Remove data
remove_data() {
    log_step "Removing data..."

    if [[ -d "${VAR_DIR}" ]]; then
        rm -rf "${VAR_DIR}"
        log_info "Removed: ${VAR_DIR}"
    else
        log_info "Data directory not found (already removed?)"
    fi
}

# Remove logs
remove_logs() {
    log_step "Removing logs..."

    if [[ -d "${LOG_DIR}" ]]; then
        rm -rf "${LOG_DIR}"
        log_info "Removed: ${LOG_DIR}"
    else
        log_info "Log directory not found (already removed?)"
    fi
}

# Print usage
usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --keep-config   Keep configuration files"
    echo "  --keep-data     Keep data files (database, logs)"
    echo "  --keep-logs     Keep log files only"
    echo "  --help          Show this help message"
    echo ""
    echo "This script removes:"
    echo "  Binary:        ${BIN_DIR}/${BINARY_NAME}"
    echo "  Configuration: ${ETC_DIR}/"
    echo "  Data:          ${VAR_DIR}/"
    echo "  Logs:          ${LOG_DIR}/"
    echo "  Service:       ${LAUNCHD_DIR}/${PLIST_NAME}"
    echo "  PF Rules:      ${PF_ANCHOR}"
}

# Confirm uninstallation
confirm() {
    echo ""
    echo "This will remove HomeGuard from your system."
    echo ""
    read -p "Are you sure you want to continue? [y/N] " -n 1 -r
    echo ""

    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_info "Uninstallation cancelled"
        exit 0
    fi
}

# Main function
main() {
    local keep_config=false
    local keep_data=false
    local keep_logs=false

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --keep-config)
                keep_config=true
                shift
                ;;
            --keep-data)
                keep_data=true
                keep_logs=true
                shift
                ;;
            --keep-logs)
                keep_logs=true
                shift
                ;;
            --help|-h)
                usage
                exit 0
                ;;
            -y|--yes)
                # Skip confirmation
                shift
                ;;
            *)
                log_error "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done

    echo ""
    echo "=========================================="
    echo "     HomeGuard Uninstallation Script      "
    echo "=========================================="
    echo ""

    # Check root
    check_root

    # Confirm
    confirm

    # Uninstallation steps
    remove_launchd
    disable_pf
    remove_binary

    if [[ "$keep_config" == false ]]; then
        remove_config
    else
        log_warn "Keeping configuration (--keep-config)"
    fi

    if [[ "$keep_data" == false ]]; then
        remove_data
    else
        log_warn "Keeping data (--keep-data)"
    fi

    if [[ "$keep_logs" == false ]]; then
        remove_logs
    else
        log_warn "Keeping logs (--keep-logs)"
    fi

    # Remove PF backup if exists and config was removed
    if [[ "$keep_config" == false && -f "${PF_CONF_BACKUP}" ]]; then
        rm -f "${PF_CONF_BACKUP}"
        log_info "Removed PF configuration backup"
    fi

    echo ""
    echo "=========================================="
    echo "       Uninstallation Complete!           "
    echo "=========================================="
    echo ""

    if [[ "$keep_config" == true ]]; then
        echo "Configuration kept at: ${ETC_DIR}/"
    fi
    if [[ "$keep_data" == true ]]; then
        echo "Data kept at: ${VAR_DIR}/"
    fi
    if [[ "$keep_logs" == true && "$keep_data" == false ]]; then
        echo "Logs kept at: ${LOG_DIR}/"
    fi

    echo ""
    echo "HomeGuard has been removed from your system."
    echo ""
}

main "$@"
