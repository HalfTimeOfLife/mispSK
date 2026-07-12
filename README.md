# mispSK - MISP Script Kit

A collection of Python scripts automating operations on MISP instances (via PyMISP).

---

## Scripts
 
| Script | Description | Status |
|---|---|---|
| `event_search.py` | Fast event/IOC lookup and summary | WIP |
| `ioc_enrich.py` | Hash/IP enrichment (VirusTotal, AbuseIPDB) | Planned |
| `feed_health.py` | Feed sync/freshness check | Planned |
| `export_attack_layer.py` | Export to ATT&CK Navigator layer JSON | Planned |
| `export_splunk.py` | Export to Splunk-ingestible format | Planned |
| `export_yara.py` | Generate YARA rules from attributes | Planned |
| `taxonomy_check.py` | Event quality/taxonomy compliance check | Planned |
| `event_import.py` | Structured event import from CTI reports | Planned |
 
See [ROADMAP.md](ROADMAP.md) for release details.

---

## Project structure
 
```
mispSK/
├── mispsk/
│   ├── client.py
│   ├── utils.py
│   └── __init__.py
├── scripts/
│   └── event_search.py
├── tests/
│   └── test_event_search.py
├── .env.example
├── .gitignore
├── LICENSE
├── pyproject.toml
├── README.md
├── ROADMAP.md
└── requirements.txt
```


---

## Requirements

- Python 3.10+
- A reachable MISP instance with API access
- A MISP API key with appropriate read/write permissions
- (Optional, per script) API keys for VirusTotal / AbuseIPDB

---

## Installation

```bash
git clone https://github.com/HalfTimeOfLife/mispSK.git
cd mispSK
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install -e .
```

---

## Configuration

Copy the example env file and fill in your instance details:

```bash
cp .env.example .env
```

```
MISP_URL=https://misp.example.local
MISP_API_KEY=your-misp-api-key
MISP_VERIFY_SSL=true

VT_API_KEY=your-virustotal-api-key
ABUSEIPDB_API_KEY=your-abuseipdb-api-key
```

---

## Usage
  
### event_search.py
 
#### Search by ID

```bash
python scripts/event_search.py --id 1234
```

#### Search by IOC

```bash
python scripts/event_search.py --ioc <IOC_VALUE>
```

#### Search displaying format

```bash
python scripts/event_search.py --ioc <IOC_VALUE> --output json
```

> The output format is `table` by default.

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.