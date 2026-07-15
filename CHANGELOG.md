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