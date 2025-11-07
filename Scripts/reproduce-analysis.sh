#!/usr/bin/env bash
set -euo pipefail

# reproduce-analysis.sh
# Minimal reproducible script to download a public Wireshark sample PCAP,
# run Zeek/tshark extraction steps, and place sanitized outputs under `evidence/`.
#
# Usage: ./Scripts/reproduce-analysis.sh [PCAP_URL]
# If PCAP_URL is omitted, the script will use the Wireshark sample `http_with_jpegs.cap.gz`.

PCAP_URL_DEFAULT="https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/http_with_jpegs.cap.gz"
PCAP_URL="${1:-$PCAP_URL_DEFAULT}"

EVIDENCE_DIR="$(cd "$(dirname "$0")/.." && pwd)/evidence"
PCAP_BASE="$(basename "$PCAP_URL")"
PCAP_PATH="$EVIDENCE_DIR/${PCAP_BASE//\?*/}"

command_exists() { command -v "$1" >/dev/null 2>&1; }

echo "Reproducible analysis script"
echo "Evidence dir: $EVIDENCE_DIR"

mkdir -p "$EVIDENCE_DIR"
mkdir -p "$EVIDENCE_DIR/extracted_http"
mkdir -p "$EVIDENCE_DIR/zeek"

download_pcap() {
  if [ -f "$PCAP_PATH" ]; then
    echo "PCAP already exists at $PCAP_PATH — skipping download"
    return 0
  fi

  echo "Downloading PCAP from: $PCAP_URL"
  if command_exists wget; then
    wget -O "$PCAP_PATH" "$PCAP_URL"
  elif command_exists curl; then
    curl -L -o "$PCAP_PATH" "$PCAP_URL"
  else
    echo "ERROR: neither wget nor curl is available. Please install one and re-run." >&2
    return 2
  fi
}

decompress_if_needed() {
  if [[ "$PCAP_PATH" == *.gz ]]; then
    echo "Decompressing $PCAP_PATH"
    if command_exists gunzip; then
      gunzip -f "$PCAP_PATH"
      PCAP_PATH="${PCAP_PATH%.gz}"
    else
      echo "ERROR: gunzip not found. Please install gzip utilities." >&2
      return 3
    fi
  fi
}

run_tshark_extracts() {
  if ! command_exists tshark; then
    echo "WARNING: tshark not found — skipping tshark steps (export-objects, timeline)." >&2
    return 0
  fi

  echo "Exporting HTTP objects (if any)"
  tshark -r "$PCAP_PATH" --export-objects http,"$EVIDENCE_DIR/extracted_http" || true

  echo "Generating timeline CSV"
  tshark -r "$PCAP_PATH" -T fields -e frame.time_epoch -e ip.src -e ip.dst -e _ws.col.Protocol -e frame.len -E header=y -E separator=',' > "$EVIDENCE_DIR/tshark-timeline.csv" || true

  echo "Computing SHA256 hashes for extracted objects"
  if command_exists shasum; then
    shasum -a 256 "$EVIDENCE_DIR/extracted_http"/* 2>/dev/null || true > "$EVIDENCE_DIR/extracted_http.hashes" || true
  elif command_exists sha256sum; then
    sha256sum "$EVIDENCE_DIR/extracted_http"/* 2>/dev/null || true > "$EVIDENCE_DIR/extracted_http.hashes" || true
  else
    echo "No SHA256 utility found (shasum/sha256sum); skipping hash generation." >&2
  fi
}

run_zeek() {
  if ! command_exists zeek; then
    echo "Zeek not installed or not in PATH — skipping Zeek logs generation." >&2
    return 0
  fi

  echo "Running Zeek to generate logs (conn.log, http.log, dns.log)"
  pushd "$EVIDENCE_DIR/zeek" >/dev/null
  zeek -r "$PCAP_PATH" || true
  popd >/dev/null
}

main() {
  download_pcap
  decompress_if_needed
  run_tshark_extracts
  run_zeek

  echo "Done. Sanitized outputs are under: $EVIDENCE_DIR"
  echo "If you plan to commit raw PCAPs, consider policy/licensing and avoid adding known-malicious payloads to public repos."
}

main "$@"
