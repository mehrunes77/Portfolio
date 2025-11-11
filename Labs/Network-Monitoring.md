# Networking-monitoring.md

## Purpose
This document defines a small, repeatable script and workflow to collect, extract, deduplicate, and sanitize network artifacts (pcap, HTTP objects) for a portfolio or investigation. It is designed to:
- produce reproducible captures,
- extract useful artifacts for analysis,
- deduplicate by hash,
- create sanitized, non-executable copies suitable for public storage,
- log all actions for traceability.

Use this in a lab/controlled environment only. Do not capture traffic on networks you do not own or have permission to monitor.

## Prerequisites
- tcpdump, tshark (Wireshark command-line), sha256sum (or shasum -a 256)
- bash (POSIX-compatible)
- sufficient disk space for pcaps and extracted files

Install on macOS (example):
- brew install wireshark
- tcpdump is typically preinstalled or use brew install tcpdump

## Files produced
- captures/capture.pcap — raw capture (keep private)
- captures/http_only.pcap — filtered pcap with HTTP
- extracted_http/ — raw extracted HTTP objects (originals; keep private)
- sanitized_outputs/ — small, safe artifacts suitable for inclusion in repos
- logs/monitoring.log — timestamped action log
- hashes/hashes.txt — sha256 hashes of extracted objects
- duplicates/ — moved duplicate files (kept private)

## Lightweight script (network-monitoring.sh)
Place this script alongside the markdown, make executable (chmod +x). It is conservative: it does not publish raw binaries and creates sanitized metadata/hexdumps for safe review.

```bash
#!/usr/bin/env bash
set -euo pipefail

# Config
OUTDIR="$(pwd)/network-monitoring-output"
CAPDIR="$OUTDIR/captures"
EXDIR="$OUTDIR/extracted_http"
SANDIR="$OUTDIR/sanitized_outputs"
HASHDIR="$OUTDIR/hashes"
DUPDIR="$OUTDIR/duplicates"
LOG="$OUTDIR/logs/monitoring.log"
CAPFILE="$CAPDIR/capture.pcap"
HTTPPCAP="$CAPDIR/http_only.pcap"

mkdir -p "$CAPDIR" "$EXDIR" "$SANDIR" "$HASHDIR" "$DUPDIR" "$(dirname "$LOG")"

log() { printf '%s %s\n' "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" "$*" | tee -a "$LOG"; }

log "START capture workflow"

# 1) Capture (example: capture 1000 packets; adjust filter as needed)
# NOTE: run with appropriate privileges; DO NOT run on networks without permission.
# macOS: use 'en0' for Wi-Fi or 'en1' for Ethernet; use 'lo0' for localhost testing
log "Running tcpdump to capture packets"
tcpdump -i any -s 0 -c 1000 -w "$CAPFILE" 'not port 22' 2>>"$LOG" || log "tcpdump finished/failed"

# 2) Filter HTTP traffic to smaller pcap
log "Filtering HTTP traffic with tshark"
tshark -r "$CAPFILE" -Y "http" -w "$HTTPPCAP" 2>>"$LOG" || log "tshark filter finished/failed"

# 3) Extract HTTP objects (creates files in $EXDIR)
log "Exporting HTTP objects"
tshark -r "$HTTPPCAP" --export-objects http,"$EXDIR" 2>>"$LOG" || log "tshark export finished/failed"

# 4) Hash and deduplicate by sha256 (keep first instance, move duplicates)
log "Hashing extracted objects and deduplicating"
cd "$EXDIR"
find . -type f -print0 | xargs -0 shasum -a 256 | sed 's/^\.\///' | sort > "$HASHDIR/hashes_raw.txt"
awk ' { if (!seen[$1]++) { print $0 > "'"$HASHDIR"'/hashes.txt"; split($0,a," "); kept[a[2]]=1 } else { print $0 > "'"$DUPDIR"'/duplicates_list.txt"; print a[2] }}' "$HASHDIR/hashes_raw.txt" || true

# Move duplicate files to duplicates dir (if duplicates_list.txt exists)
if [ -f "$DUPDIR/duplicates_list.txt" ]; then
    log "Moving duplicates to $DUPDIR"
    while IFS= read -r line; do
        # lines are "<hash>  ./path"
        fname="$(echo "$line" | awk '{print $2}')"
        # remove leading ./ if present
        fname="${fname#./}"
        mkdir -p "$DUPDIR/$(dirname "$fname")"
        mv -n -- "$fname" "$DUPDIR/$fname" || true
    done < "$DUPDIR/duplicates_list.txt"
fi

# 5) Sanitize: generate metadata + limited hexdump (first 512 bytes) and remove exec perms
log "Sanitizing kept artifacts into $SANDIR"
cd "$EXDIR"
find . -type f -print0 | while IFS= read -r -d '' f; do
    f="${f#./}"
    target_meta="$SANDIR/$f.meta"
    target_hex="$SANDIR/$f.hexdump"
    mkdir -p "$(dirname "$target_meta")"
    # collect metadata (macOS uses stat -f, Linux uses stat -c; both are tried)
    size=$(stat -f%z "$f" 2>/dev/null || stat -c%s "$f" 2>/dev/null || echo "unknown")
    mime=$(file -b --mime-type "$f" 2>/dev/null || echo "unknown")
    sha=$(shasum -a 256 "$f" | awk '{print $1}' 2>/dev/null || echo "unknown")
    printf 'filename: %s\nsize: %s\nmime: %s\nsha256: %s\n' "$f" "$size" "$mime" "$sha" > "$target_meta"
    # limited hexdump (first 512 bytes) for safe inspection
    dd if="$f" bs=1 count=512 2>/dev/null | hexdump -C > "$target_hex" || true
    # ensure no execute permission on sanitized outputs
    chmod a-x "$target_meta" "$target_hex" || true
done

# 6) Strip execute bit from original extracted files (defensive)
log "Stripping executable permissions from original extracted files"
find "$EXDIR" -type f -exec chmod a-x {} \; || true

log "FINISH capture workflow. Outputs: $OUTDIR"
```

Notes about the script
- It keeps raw artifacts in a private folder (network-monitoring-output/captures and /extracted_http). Do not add those raw artifacts to public repos.
- sanitized_outputs/ contains only small metadata and the first 512 bytes in hex; safe for inclusion in a portfolio.
- Deduplication uses sha256; duplicates are moved to duplicates/.
- The script logs all steps to logs/monitoring.log for auditability.

## How to use
1. Copy the script to your lab machine, review and adjust packet capture filters and packet count.
2. Run with appropriate privileges: `sudo ./network-monitoring.sh`
3. Review logs and sanitized_outputs before adding anything to a public repository.

## macOS-specific notes

**Network interfaces:** macOS names interfaces differently than Linux. Common examples:
- `en0` — primary network interface (often Wi-Fi)
- `en1` — secondary interface (often Ethernet if present)
- `lo0` — loopback (for testing locally)
- `any` — capture on all interfaces (works on macOS)

To list available interfaces and choose one:
```bash
ifconfig -l
# or
tcpdump -D
```

**Tools verification:** after installing via Homebrew, verify the tools work:
```bash
brew list tcpdump wireshark
which tshark
tshark --version
shasum --version
```

**Example: capture on Wi-Fi only:**
Edit the script and change `tcpdump -i any` to `tcpdump -i en0` (or your chosen interface).

**macOS permissions:** capturing packets requires sudo. Homebrew-installed tools typically work fine, but if you encounter permission issues, ensure Terminal or your shell has Full Disk Access (System Preferences > Security & Privacy > Privacy > Full Disk Access).

## Purpose explanation (concise)
This document + script provide a minimal, auditable pipeline to:
- capture network traffic for analysis,
- extract HTTP artifacts,
- deduplicate and track provenance via hashes,
- create sanitized, non-executable representations safe for public sharing,
- log all actions to support reproducibility and review.

It is intended for training, portfolio demonstration, and controlled analysis — not for production-scale monitoring.

## Safety checklist (before publishing artifacts)
- Ensure raw pcaps and original extracted binaries remain private
- Include only sanitized metadata/hexdumps in repos
- Verify no executable permissions on published files
- Keep logs of what was changed/moved for traceability

---
End of Networking-monitoring.md