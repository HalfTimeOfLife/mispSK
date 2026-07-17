# CHANGELOG

All notable changes to mispSK are documented here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [0.1] - 2026-07-13

### Added
- `event_search.py`: lookup a MISP event by ID or IOC value
- Summary output includes event ID, event info, attribute count, attribute type breakdown, source org, TLP, and ATT&CK cluster tags
- `--output table|json` formatting
- `mispsk/client.py`: shared `MispClient` wrapper handling config loading, validation, and connection to a MISP instance
- `mispsk/utils.py`: shared summary extraction and output formatting logic
- `pyproject.toml` for editable install (`pip install -e .`)
- Unit tests covering `_get_tlp`, `_get_attack_tags`, `extract_summary`, and `format_output`

---

## [0.2] - 2026-07-15

### Added
- `ioc_enrich.py`: hash lookup (md5/sha1/sha256) via VirusTotal, IP lookup (ip-src/ip-dst) via AbuseIPDB
- `mispsk/enrichers.py`: `VTEnricher` and `AbuseIPDBEnricher` wrappers, classification thresholds (`VT_THRESHOLDS`, `ABUSEIPDB_THRESHOLDS`)
- `mispsk/utils.py`: `classify_vt_result`, `classify_abuseipdb_result` `build_enrichment_comment`, `build_enrichment_tag`, `build_tree_output`, `HASH_TYPES`, `IP_TYPES`
- `mispsk/client.py`: `get_event_by_id`, `get_events_by_ioc` methods (moved from `event_search.py` for reuse across scripts)
- `tests/test_enrichers.py`: unit tests covering VirusTotal and AbuseIPDB API responses, errors, rate limiting, and normalization
- `tests/test_enrichment.py`: unit tests covering IOC enrichment workflow, caching, dry-run mode, skipped attributes, and API failures
- `tests/test_client.py`: unit tests covering MISP event lookup methods
- `--dry-run` and `--max-age-days` flags
- Tree-style terminal output for enrichment results
- `VT_RATE_LIMIT_DELAY` env var to control VirusTotal free-tier throttling

### Changed
- `event_search.py`: now uses `MispClient.get_event_by_id` / `get_events_by_ioc` instead of local functions
- MISP API interaction logic moved from scripts into reusable `mispsk` package modules
- Enrichment logic separated from CLI handling for better testability and reuse

### Fixed
- Removed duplicated MISP event lookup logic from scripts
- Improved enrichment workflow reliability with IOC lookup caching

---

## [0.2.1] - 2026-07-15

### Fixed
- `mispsk/utils.py`: corrected composite attribute handling (`filename|md5`, `ip-src|port`, etc.) - hash/IP value is now extracted from the correct segment (position varies by type), fixing a bug where port numbers were sent to AbuseIPDB as IP addresses (422 errors)
- `mispsk/enrichment.py`: comment and tag updates are now independent - a changed comment no longer forces an unnecessary tag re-application, and vice versa
- `mispsk/enrichment.py`: unexpected HTTP errors (5xx) from VirusTotal/AbuseIPDB now stop enrichment gracefully instead of raising an unhandled traceback
- `mispsk/client.py`: connection error message translated to English for consistency

### Added
- `mispsk/utils.py`: `extract_ioc_value`, `COMPOSITE_HASH_TYPES`, `COMPOSITE_IP_TYPES`, `COMPOSITE_IOC_POSITION`
- `requirements-dev.txt`: separated dev-only dependencies (`pytest`, `requests-mock`) from runtime requirements
- Test coverage for composite attribute extraction and caching

---

## [0.3] - 2026-07-17

### Added
- `feed_health.py`: reports sync status and matched event volume per configured MISP feed
- `mispsk/feeds.py`: `resolve_last_sync`, `resolve_recent_volume`, `build_result`
- `mispsk/utils.py`: `get_age`, `build_feed_report`
- `--max-age-days` flag to control the staleness threshold for `fixed_event` feeds

### Changed
- `event_search.py`: table output now uses `rounded_grid` formatting for visual consistency with `feed_health.py`

### Known limitation
- Sync freshness (`last_sync`) is only resolvable for `fixed_event` feeds. For all other feeds (`misp`/`csv`/`freetext` without a reused event), MISP exposes no reliable "last successful fetch" signal via PyMISP:
  - `event.timestamp` reflects the source's original publish date
  - `search_logs()` does not journal feed fetches