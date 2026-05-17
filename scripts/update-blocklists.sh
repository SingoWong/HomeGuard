#!/bin/bash
#
# HomeGuard Blocklist Updater
#
# Fetches curated category blocklists from upstream open-source sources
# and writes them into HomeGuard's expected layout:
#   <dest>/<category>.list   (one suffix-form domain per line, "." prefix)
#
# Sources:
#   - UT1 Toulouse blacklists (academic, category-rich, weekly):
#       https://dsi.ut-capitole.fr/blacklists/
#   - Hagezi DNS Blocklists (frequent updates, used for threat-intel only):
#       https://github.com/hagezi/dns-blocklists
#
# Categories handled:
#   porn     <- UT1/adult
#   gambling <- UT1/gambling
#   violence <- UT1/agressif
#   drugs    <- UT1/drogue
#   weapons  <- UT1/dangerous_material
#   piracy   <- UT1/warez
#   malware  <- Hagezi/tif
#
# Why mostly UT1: as of 2026, Hagezi consolidated its standalone categorical
# lists (nsfw/gambling/piracy) into umbrella files (pro.plus, ultimate) that
# can't be split back out without false positives. UT1 keeps clean per-category
# tarballs, making it the better source for category-discriminated blocking.
# We keep Hagezi/tif because UT1 doesn't ship a comparable threat-intel feed.
#
# Per-category writes are atomic: each list is built in a temp file and only
# moved into place after every source for that category succeeds. A single
# source failure aborts that category but leaves the existing file intact.
#
# Usage:
#   ./scripts/update-blocklists.sh                     # update all categories
#   ./scripts/update-blocklists.sh -c porn -c gambling # subset
#   ./scripts/update-blocklists.sh --dry-run           # preview, no writes
#   ./scripts/update-blocklists.sh --dest /usr/local/etc/homeguard/blocklists/categories
#   ./scripts/update-blocklists.sh --reload            # kickstart com.homeguard after
#
# Cron-friendly: exit 0 if >=1 category succeeded, 1 if all failed, 2 on
# usage error. Designed to be wrapped in:
#   0 3 * * 0  /opt/homeguard/scripts/update-blocklists.sh --reload >> /var/log/homeguard/update.log 2>&1
#

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "${SCRIPT_DIR}")"

# Default destination: project-relative; override with --dest for installed deploys
DEFAULT_DEST="${PROJECT_DIR}/config/blocklists/categories"

# UT1 tarball base URL
UT1_BASE="https://dsi.ut-capitole.fr/blacklists/download"

# Hagezi raw domain list base URL
HAGEZI_BASE="https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains"

# Categories the script knows how to populate. Add by extending the case
# statement in `fetch_category` below.
ALL_CATEGORIES=(porn gambling violence drugs weapons piracy malware)

# ---------------------------------------------------------------------------
# Output helpers (color if stdout is a TTY)
# ---------------------------------------------------------------------------

if [ -t 1 ]; then
    C_R=$'\033[0;31m'; C_G=$'\033[0;32m'; C_Y=$'\033[1;33m'; C_B=$'\033[0;34m'; C_N=$'\033[0m'
else
    C_R=''; C_G=''; C_Y=''; C_B=''; C_N=''
fi

QUIET=0
log()  { [ "$QUIET" = "1" ] || echo "${C_B}[update]${C_N} $*"; }
ok()   { [ "$QUIET" = "1" ] || echo "${C_G}[  ok  ]${C_N} $*"; }
warn() { echo "${C_Y}[ warn ]${C_N} $*" >&2; }
err()  { echo "${C_R}[error]${C_N} $*" >&2; }

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

usage() {
    sed -n '3,/^$/p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    cat <<EOF

Options:
  -d, --dest DIR       Output directory (default: ${DEFAULT_DEST})
  -c, --category CAT   Category to update; repeatable. Default: all
                       Choices: ${ALL_CATEGORIES[*]}
  -n, --dry-run        Show what would be downloaded; write nothing
  -q, --quiet          Suppress progress output (errors still printed)
      --reload         After successful update, sudo launchctl kickstart -k system/com.homeguard
  -h, --help           Show this help and exit
EOF
}

DEST="$DEFAULT_DEST"
DRY_RUN=0
RELOAD=0
SELECTED=()

while [ $# -gt 0 ]; do
    case "$1" in
        -d|--dest)     DEST="$2"; shift 2 ;;
        -c|--category) SELECTED+=("$2"); shift 2 ;;
        -n|--dry-run)  DRY_RUN=1; shift ;;
        -q|--quiet)    QUIET=1; shift ;;
        --reload)      RELOAD=1; shift ;;
        -h|--help)     usage; exit 0 ;;
        *)             err "unknown option: $1"; usage >&2; exit 2 ;;
    esac
done

if [ ${#SELECTED[@]} -eq 0 ]; then
    SELECTED=("${ALL_CATEGORIES[@]}")
fi

# Validate selections
for cat in "${SELECTED[@]}"; do
    found=0
    for known in "${ALL_CATEGORIES[@]}"; do
        if [ "$cat" = "$known" ]; then found=1; break; fi
    done
    if [ $found -eq 0 ]; then
        err "unknown category: $cat (known: ${ALL_CATEGORIES[*]})"
        exit 2
    fi
done

# ---------------------------------------------------------------------------
# Fetchers — write *one* normalized stream (HomeGuard suffix form) to stdout.
# Any non-zero exit aborts the caller's category build.
# ---------------------------------------------------------------------------

# Strip lines that aren't plausible domains, then prefix with "." to make
# them suffix matches in HomeGuard's BlocklistManager (covers all subdomains).
normalize_domains() {
    awk '
        # skip blanks and comments
        /^[[:space:]]*$/ || /^[[:space:]]*[#!]/ { next }
        # accept lowercase a-z, digits, dot, dash; require >=1 dot; min length 4
        {
            d = tolower($0)
            sub(/[[:space:]]+$/, "", d)
            sub(/^[[:space:]]+/, "", d)
            if (d ~ /^[a-z0-9.-]+\.[a-z]{2,}$/ && length(d) >= 4) {
                print "." d
            }
        }
    '
}

# UT1 hosts file lines look like "0.0.0.0 example.com"; tarball domains/
# directory just has plain domains. Both go through normalize_domains.
fetch_ut1_category() {
    local ut1_name="$1"  # e.g. "adult", "gambling", "drogue", "agressif"
    local tmpdir
    tmpdir="$(mktemp -d)"
    trap "rm -rf '$tmpdir'" RETURN

    local tarball="${tmpdir}/${ut1_name}.tar.gz"
    if ! curl -fsSL "${UT1_BASE}/${ut1_name}.tar.gz" -o "$tarball"; then
        err "UT1: failed to download ${ut1_name}.tar.gz"
        return 1
    fi
    if ! tar -xzf "$tarball" -C "$tmpdir"; then
        err "UT1: failed to extract ${ut1_name}.tar.gz"
        return 1
    fi
    # UT1 layout: <category>/domains (and usually /urls, /expressions etc.)
    local domains_file="${tmpdir}/${ut1_name}/domains"
    if [ ! -f "$domains_file" ]; then
        err "UT1: ${ut1_name}/domains not found in tarball"
        return 1
    fi
    normalize_domains < "$domains_file"
}

# Hagezi serves plain one-domain-per-line lists.
fetch_hagezi() {
    local list_name="$1"  # e.g. "nsfw", "gambling", "tif", "piracy"
    local tmp
    tmp="$(mktemp)"
    trap "rm -f '$tmp'" RETURN

    if ! curl -fsSL "${HAGEZI_BASE}/${list_name}.txt" -o "$tmp"; then
        err "Hagezi: failed to download ${list_name}.txt"
        return 1
    fi
    normalize_domains < "$tmp"
}

# ---------------------------------------------------------------------------
# Category → source pipeline. Each case writes a complete stream to stdout
# (concatenation of all source feeds, sort -u'd by the caller).
# ---------------------------------------------------------------------------

fetch_category() {
    local cat="$1"
    case "$cat" in
        porn)     fetch_ut1_category adult              ;;
        gambling) fetch_ut1_category gambling           ;;
        violence) fetch_ut1_category agressif           ;;
        drugs)    fetch_ut1_category drogue             ;;
        weapons)  fetch_ut1_category dangerous_material ;;
        piracy)   fetch_ut1_category warez              ;;
        malware)  fetch_hagezi      tif                 ;;
        *)        err "no fetcher defined for category: $cat"; return 1 ;;
    esac
}

# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

if [ "$DRY_RUN" = "0" ]; then
    mkdir -p "$DEST"
fi

succeeded=()
failed=()

for cat in "${SELECTED[@]}"; do
    log "category: ${cat}"
    tmp="$(mktemp)"

    if fetch_category "$cat" > "$tmp"; then
        # dedupe + stable sort
        sort -u -o "$tmp" "$tmp"
        new_count=$(wc -l < "$tmp" | tr -d ' ')

        if [ "$new_count" = "0" ]; then
            err "category ${cat}: 0 domains after normalization; refusing to overwrite"
            failed+=("$cat")
            rm -f "$tmp"
            continue
        fi

        dest_file="${DEST}/${cat}.list"
        old_count=0
        if [ -f "$dest_file" ]; then
            old_count=$(grep -cE '^\.[a-z]' "$dest_file" 2>/dev/null || echo 0)
        fi

        if [ "$DRY_RUN" = "1" ]; then
            ok "${cat}: ${new_count} domains (was ${old_count}) — dry-run, not written"
            rm -f "$tmp"
        else
            # Prepend a header comment so the source is traceable
            header_tmp="$(mktemp)"
            {
                echo "# HomeGuard blocklist: ${cat}"
                echo "# Generated by scripts/update-blocklists.sh at $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
                echo "# DO NOT EDIT BY HAND — your changes will be overwritten on next run."
                echo "# To add manual exceptions, use a separate file in this directory."
                echo "#"
                cat "$tmp"
            } > "$header_tmp"
            mv "$header_tmp" "$dest_file"
            chmod 644 "$dest_file"
            rm -f "$tmp"
            ok "${cat}: ${new_count} domains (was ${old_count}) -> ${dest_file}"
        fi

        succeeded+=("$cat")
    else
        err "category ${cat}: skipped (source fetch failed); existing file untouched"
        failed+=("$cat")
        rm -f "$tmp"
    fi
done

# ---------------------------------------------------------------------------
# Summary + optional reload
# ---------------------------------------------------------------------------

echo
if [ ${#succeeded[@]} -gt 0 ]; then
    log "succeeded: ${succeeded[*]}"
fi
if [ ${#failed[@]} -gt 0 ]; then
    warn "failed:    ${failed[*]}"
fi

if [ "$DRY_RUN" = "0" ] && [ "$RELOAD" = "1" ] && [ ${#succeeded[@]} -gt 0 ]; then
    log "reloading homeguard (sudo launchctl kickstart -k system/com.homeguard)"
    if sudo launchctl kickstart -k system/com.homeguard; then
        ok "homeguard reloaded"
    else
        warn "kickstart returned non-zero; check 'sudo launchctl list | grep homeguard'"
    fi
elif [ "$DRY_RUN" = "0" ] && [ ${#succeeded[@]} -gt 0 ]; then
    log "lists updated. To pick them up: sudo launchctl kickstart -k system/com.homeguard"
fi

# Exit code: 0 if anything succeeded, 1 if everything failed
if [ ${#succeeded[@]} -gt 0 ]; then
    exit 0
else
    exit 1
fi
