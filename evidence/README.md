# Evidence (sanitized)

This directory contains sanitized outputs from a local packet-analysis reproducible pipeline. Raw PCAPs and extracted binary objects are intentionally NOT committed to this repository for safety and legal reasons.

What is included
- `tshark-timeline.csv` — lightweight timeline CSV derived from the capture (timestamp, src, dst, proto, length).
- `extracted_http.hashes` — SHA256 hashes for HTTP-extracted objects (to show evidence without preserving the objects themselves).
- `zeek/` — sanitized Zeek logs (e.g., `conn.log`, `http.log`) showing network metadata and HTTP transactions.

What was removed
- The directory `evidence/extracted_http/` (local extracted images, HTML, and objects) was intentionally untracked and is listed in `.gitignore`.

Why we remove raw artifacts
- Image/HTML files and other HTTP objects may contain active content or weaponized payloads that could be harmful if stored in a public repo.
- Keeping only hashes and sanitized logs preserves reproducibility and demonstrates analysis while minimizing risk.

How to reproduce locally
1. Ensure you have the required tools installed: `tshark`, `tox`, `zeek` (or `bro`), `curl`/`wget`, `sha256sum` (or `shasum -a 256` on macOS).
2. Make the reproduce script executable and run it locally (it will download a sample PCAP, extract objects into `evidence/extracted_http/` locally, compute hashes, and write sanitized logs/hashes):

```bash
chmod +x Scripts/reproduce-analysis.sh
./Scripts/reproduce-analysis.sh
```

If you want the extracted objects to be kept locally but not committed, they will remain on your machine in `evidence/extracted_http/` after running the script because that folder is ignored by git.

If you'd like me to purge any previously committed extracted files from the repository history, I can provide the safe sequence using the BFG or `git filter-repo`. Note: purging rewrites history and requires force-pushing; coordinate with collaborators before proceeding.

Contact / notes
- If you want me to run the purge now, reply with: `Purge now` — I will then run the mirror/cleanup and force-push steps after confirming the branch and remote.
This directory contains sanitized, example outputs produced for the "http_with_jpegs.cap" case study used in
`Labs/Incident-Response.md`.

Files included (sanitized):
- `extracted_http.hashes` — SHA256 hashes for HTTP objects (example values, not raw binaries).
- `tshark-timeline.csv` — simplified packet timeline extracted via tshark (sanitized/tiny sample).
- `zeek/conn.log` and `zeek/http.log` — minimal Zeek logs produced for the case study (sanitized).

Notes:
- These files are illustrative and intended for portfolio display and reproducibility guidance. They are not raw PCAPs or executable artifacts.
- To reproduce real outputs locally, place the PCAP into this directory and run the commands listed in `Labs/Incident-Response-changelog.md` or `Labs/Incident-Response.md`.
