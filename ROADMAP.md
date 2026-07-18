# ROADMAP - mispSK

---

## v0.5.1 - YARA Export
- `export_yara.py`: generates YARA rules from filename/pattern-type attributes
- `mispsk/export_common.py`: shared export/filter core, designed for reuse by export_splunk.py (v0.5.2)

---

## v0.5.2 - Splunk Export
- `export_splunk.py`: exports attributes to a Splunk-ingestible CSV/CIM format
- Reuses `export_common.py` introduced in v0.5.1

---

## v0.6 - Taxonomy & Quality Check
- `taxonomy_check.py`: validates events against a minimal quality baseline (TLP present, ATT&CK tag present, classification tag present)
- Outputs a non-compliance report (`--output table|csv`)

---

## v0.7 - Structured Event Import
- `event_import.py`: builds a MISP event from a defined CTI report structure (attributes, tags, ATT&CK mapping)
- Compatible with the report format used in my Wine/APT29 (GRAPELOADER) analysis

---

## v1.0 - Consolidation
- Full README coverage for all scripts
- Basic test suite (`tests/`) covering the shared `mispsk/` core and dry-run paths
- Packaging cleanup (pinned `requirements.txt`, consistent CLI flags across all scripts)
- Tagged GitHub release

---
 
## Status summary
 
| Version | Script(s) | Status |
|---|---|---|
| v0.1 | `event_search.py` | Shipped |
| v0.2 | `ioc_enrich.py` | Shipped |
| v0.3 | `feed_health.py` | Shipped |
| v0.4 | `export_attack_layer.py` | Shipped |
| v0.5.1 | `export_yara.py` | Planned |
| v0.5.2 | `export_splunk.py` | Planned |
| v0.6 | `taxonomy_check.py` | Planned |
| v0.7 | `event_import.py` | Planned |
| v1.0 | Consolidation | Planned |
