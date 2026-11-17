# trusttrain (Python SDK and CLI)

Client library and command-line tool for the TrustTrain API, plus offline
dataset fingerprinting that works without a server.

```bash
pip install ./sdk
```

```python
from trusttrain import TrustTrain

security = TrustTrain(api_url="http://localhost:8000")  # reads TRUSTTRAIN_TOKEN or TRUSTTRAIN_EMAIL/PASSWORD
report = security.inspect_dataset("./training-data")
print(report.risk_level)
```

```bash
trusttrain init --dataset data/train.csv
trusttrain fingerprint data/train.csv
trusttrain verify data/train.csv
trusttrain inspect data/train.csv --fail-on high
trusttrain lineage --dataset <DATASET_ID>
trusttrain report --incident <INCIDENT_ID>
trusttrain ci --output trusttrain-report.json
```

See the repository README and `docs/API_REFERENCE.md` for details.
