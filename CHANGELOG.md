# CHANGELOG

All notable changes to mispSK are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [0.1] - 2026-07-13

### Added
- `event_search.py`: lookup a MISP event by ID or IOC value
- Summary output includes event ID, event info, attribute count, attribute
  type breakdown, source org, TLP, and ATT&CK cluster tags
- `--output table|json` formatting
- `mispsk/client.py`: shared `MispClient` wrapper handling config loading,
  validation, and connection to a MISP instance
- `mispsk/utils.py`: shared summary extraction and output formatting logic
- `pyproject.toml` for editable install (`pip install -e .`)
- Unit tests covering `_get_tlp`, `_get_attack_tags`, `extract_summary`, and
  `format_output`

---