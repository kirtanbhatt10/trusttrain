"""``trusttrain`` command-line interface.

Commands
--------
init         create .trusttrain/config.json
fingerprint  write a manifest for a dataset file (offline)
verify       check a dataset file against its manifest (offline)
inspect      upload and inspect a dataset on the server
lineage      show downstream artifacts of a dataset
report       print an incident investigation report
ci           policy-driven checks for CI pipelines (writes a JSON report)

Exit codes: 0 success, 1 policy/integrity failure, 2 usage or runtime error.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, TextIO

from trusttrain import __version__
from trusttrain.client import TrustTrain
from trusttrain.local import LocalDatasetError, fingerprint, verify
from trusttrain.models import RISK_ORDER, DirectoryReport, InspectionReport, TrustTrainError, risk_at_least

CONFIG_DIR = Path(".trusttrain")
CONFIG_FILE = CONFIG_DIR / "config.json"
DEFAULT_CONFIG: dict[str, Any] = {
    "api_url": "http://localhost:8000",
    "manifests_dir": ".trusttrain/manifests",
    "datasets": [],
    "policy": {"fail_on_integrity_mismatch": True, "fail_on_missing_manifest": True, "fail_on_risk": "high", "inspect_via_api": False},
}
_SEV_COLOUR = {"critical": "\033[1;31m", "high": "\033[31m", "medium": "\033[33m", "low": "\033[36m", "info": "\033[2m"}


class _Out:
    def __init__(self, stream: TextIO) -> None:
        self.stream = stream
        self.colour = stream.isatty() and "NO_COLOR" not in os.environ

    def line(self, text: str = "") -> None:
        print(text, file=self.stream)

    def sev(self, severity: str) -> str:
        label = f"{severity.upper():<8}"
        return f"{_SEV_COLOUR.get(severity, '')}{label}\033[0m" if self.colour else label


def load_config(path: Path = CONFIG_FILE) -> dict[str, Any]:
    config = json.loads(json.dumps(DEFAULT_CONFIG))
    if path.exists():
        user = json.loads(path.read_text())
        policy = {**config["policy"], **user.get("policy", {})}
        config.update(user)
        config["policy"] = policy
    if os.environ.get("TRUSTTRAIN_API_URL"):
        config["api_url"] = os.environ["TRUSTTRAIN_API_URL"]
    return config


def manifest_path_for(dataset: Path, manifests_dir: Path) -> Path:
    safe = str(dataset).replace(os.sep, "__").replace("..", "_")
    return manifests_dir / f"{safe}.manifest.json"


def _client(config: dict[str, Any]) -> TrustTrain:
    return TrustTrain(api_url=config["api_url"])


# -- commands ---------------------------------------------------------------------
def cmd_init(args: argparse.Namespace, out: _Out) -> int:
    if CONFIG_FILE.exists() and not args.force:
        out.line(f"{CONFIG_FILE} already exists (use --force to overwrite)")
        return 2
    CONFIG_DIR.mkdir(exist_ok=True)
    config = json.loads(json.dumps(DEFAULT_CONFIG))
    config["api_url"] = args.api_url
    config["datasets"] = [str(Path(d)) for d in args.dataset]
    CONFIG_FILE.write_text(json.dumps(config, indent=2) + "\n")
    Path(config["manifests_dir"]).mkdir(parents=True, exist_ok=True)
    out.line(f"Initialised TrustTrain in {CONFIG_DIR.resolve()}")
    out.line(f"  API URL:  {config['api_url']}")
    out.line(f"  Datasets: {', '.join(config['datasets']) or '(none yet — add paths to config.json)'}")
    out.line("Next: trusttrain fingerprint <dataset> and commit the manifest.")
    return 0


def cmd_fingerprint(args: argparse.Namespace, out: _Out) -> int:
    path = Path(args.path)
    manifest = fingerprint(path)
    target = Path(args.output) if args.output else manifest_path_for(path, Path(load_config()["manifests_dir"]))
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(manifest, indent=1) + "\n")
    out.line(f"Fingerprinted {path}")
    out.line(f"  format       {manifest['file']['format']}")
    out.line(f"  size         {manifest['file']['size_bytes']:,} bytes in {len(manifest['chunks']['hashes'])} chunk(s)")
    out.line(f"  sha256       {manifest['file']['sha256']}")
    out.line(f"  rows         {manifest['rows']['count']:,}  columns: {', '.join(manifest['rows']['columns'])}")
    out.line(f"  merkle root  {manifest['rows']['merkle_root']}")
    out.line(f"  duplicates   {manifest['duplicates']['exact_duplicate_rows']} exact duplicate row(s)")
    out.line(f"Manifest written to {target}")
    return 0


def cmd_verify(args: argparse.Namespace, out: _Out) -> int:
    path = Path(args.path)
    mpath = Path(args.manifest) if args.manifest else manifest_path_for(path, Path(load_config()["manifests_dir"]))
    if not mpath.exists():
        out.line(f"No manifest found at {mpath}. Run `trusttrain fingerprint {path}` first.")
        return 2
    result = verify(path, json.loads(mpath.read_text()))
    if args.json:
        out.line(json.dumps(result, indent=2))
    elif result["status"] == "verified":
        out.line(f"VERIFIED  {path} matches {mpath} (sha256 {result['actual_sha256'][:16]}…)")
    else:
        out.line(f"MODIFIED  {path} does not match {mpath}")
        out.line(f"  expected sha256 {result['expected_sha256']}")
        out.line(f"  actual sha256   {result['actual_sha256']}")
        out.line(f"  rows added: {result['rows_added']}  rows removed: {result['rows_removed']}  changed chunks: {result['changed_chunks']}")
        if result["columns_added"] or result["columns_removed"]:
            out.line(f"  columns added: {result['columns_added']}  removed: {result['columns_removed']}")
        if result["content_equivalent"]:
            out.line("  note: row content is identical; only formatting/ordering bytes changed")
    return 0 if result["status"] == "verified" else 1


def _print_report(report: InspectionReport, out: _Out) -> None:
    out.line(f"\n{report.dataset_name}  ({report.dataset_id})")
    out.line(f"  risk: {report.risk_level.upper()} (score {report.risk_score:.2f})  sha256 {report.sha256[:16]}…")
    skipped = [m for m in report.methods if m["status"] != "ran"]
    if skipped:
        out.line("  skipped: " + "; ".join(f"{m['method']} ({m['reason']})" for m in skipped))
    if not report.findings:
        out.line("  no findings")
    for f in sorted(report.findings, key=lambda f: -["info", "low", "medium", "high", "critical"].index(f.severity)):
        rows = f.evidence.get("row_indices_total")
        out.line(f"  {out.sev(f.severity)} {f.title}  [{f.method}, confidence {f.confidence:.2f}{f', {rows} rows' if rows else ''}]")


def cmd_inspect(args: argparse.Namespace, out: _Out) -> int:
    config = load_config()
    options: dict[str, Any] = {}
    for key in ("reference_dataset_id", "text_column", "label_column", "input_column", "output_column"):
        if getattr(args, key):
            options[key] = getattr(args, key)
    with _client(config) as client:
        result = client.inspect_dataset(args.path, **options)
    reports = result.reports if isinstance(result, DirectoryReport) else [result]
    if args.json:
        out.line(
            json.dumps(
                [
                    {"dataset_id": r.dataset_id, "risk_level": r.risk_level, "risk_score": r.risk_score, "findings": [f.__dict__ for f in r.findings]}
                    for r in reports
                ],
                indent=2,
            )
        )
    else:
        for r in reports:
            _print_report(r, out)
        out.line(f"\nOverall risk: {result.risk_level.upper()}")
        out.line("Findings are evidence for investigation, not proof of poisoning.")
    return 1 if args.fail_on and risk_at_least(result.risk_level, args.fail_on) else 0


def cmd_lineage(args: argparse.Namespace, out: _Out) -> int:
    with _client(load_config()) as client:
        data = client.lineage(args.dataset)
    if args.json:
        out.line(json.dumps(data, indent=2))
        return 0
    out.line(f"Downstream of dataset {args.dataset}: {data['total_affected']} recorded artifact(s)")
    for kind, items in data["affected"].items():
        out.line(f"  {kind.replace('_', ' ')} ({len(items)})")
        for item in items:
            status = f" [{item['status']}]" if item.get("status") else ""
            out.line(f"    {'  ' * (item['distance'] - 1)}└─ {item['label']}{status}  ({item['id']})")
    return 0


def cmd_report(args: argparse.Namespace, out: _Out) -> int:
    with _client(load_config()) as client:
        report = client.incident_report(args.incident, format=args.format)
    text = report if isinstance(report, str) else json.dumps(report, indent=2)
    if args.output:
        Path(args.output).write_text(text)
        out.line(f"Report written to {args.output}")
    else:
        out.line(text)
    return 0


def cmd_ci(args: argparse.Namespace, out: _Out) -> int:
    config = load_config(Path(args.config))
    policy = config["policy"]
    datasets = args.dataset or config["datasets"]
    manifests_dir = Path(config["manifests_dir"])
    report: dict[str, Any] = {
        "tool": "trusttrain",
        "version": __version__,
        "generated_at": datetime.now(UTC).isoformat(),
        "policy": policy,
        "datasets": [],
        "violations": [],
    }
    client: TrustTrain | None = None
    if policy.get("inspect_via_api"):
        client = _client(config)
    try:
        for ds in datasets:
            path = Path(ds)
            entry: dict[str, Any] = {"path": ds}
            mpath = manifest_path_for(path, manifests_dir)
            if not path.is_file():
                entry["integrity"] = "missing_file"
                report["violations"].append(f"{ds}: dataset file not found")
            elif not mpath.exists():
                entry["integrity"] = "no_manifest"
                if policy.get("fail_on_missing_manifest", True):
                    report["violations"].append(f"{ds}: no committed manifest at {mpath}")
            else:
                result = verify(path, json.loads(mpath.read_text()))
                entry["integrity"] = result["status"]
                entry["verification"] = result
                if result["status"] != "verified" and policy.get("fail_on_integrity_mismatch", True):
                    report["violations"].append(
                        f"{ds}: content differs from manifest ({result['rows_added']} added, {result['rows_removed']} removed rows)"
                    )
            if client is not None and path.is_file():
                insp = client.inspect_dataset(path)
                if not isinstance(insp, InspectionReport):  # pragma: no cover - a file path yields one report
                    raise TrustTrainError(f"Unexpected report type for {ds}")
                entry["inspection"] = {
                    "dataset_id": insp.dataset_id,
                    "risk_level": insp.risk_level,
                    "risk_score": insp.risk_score,
                    "findings": [{"severity": f.severity, "method": f.method, "title": f.title} for f in insp.findings],
                }
                threshold = policy.get("fail_on_risk")
                if threshold and threshold in RISK_ORDER and risk_at_least(insp.risk_level, threshold):
                    report["violations"].append(f"{ds}: risk {insp.risk_level} meets fail_on_risk={threshold}")
            report["datasets"].append(entry)
    finally:
        if client is not None:
            client.close()
    report["passed"] = not report["violations"]
    Path(args.output).write_text(json.dumps(report, indent=2) + "\n")
    for entry in report["datasets"]:
        risk = entry.get("inspection", {}).get("risk_level", "-")
        out.line(f"  {entry['path']}: integrity={entry['integrity']} risk={risk}")
    for v in report["violations"]:
        out.line(f"  VIOLATION {v}")
    out.line(f"TrustTrain CI {'passed' if report['passed'] else 'FAILED'}; report written to {args.output}")
    return 0 if report["passed"] else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="trusttrain", description="AI training supply chain security")
    parser.add_argument("--version", action="version", version=f"trusttrain {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("init", help="create .trusttrain/config.json")
    p.add_argument("--api-url", default=DEFAULT_CONFIG["api_url"])
    p.add_argument("--dataset", action="append", default=[], help="dataset path to track (repeatable)")
    p.add_argument("--force", action="store_true")
    p.set_defaults(func=cmd_init)

    p = sub.add_parser("fingerprint", help="write a manifest for a dataset file")
    p.add_argument("path")
    p.add_argument("-o", "--output", help="manifest output path")
    p.set_defaults(func=cmd_fingerprint)

    p = sub.add_parser("verify", help="verify a dataset file against its manifest")
    p.add_argument("path")
    p.add_argument("-m", "--manifest")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("inspect", help="upload and inspect a dataset file or directory")
    p.add_argument("path")
    p.add_argument("--reference-dataset-id", dest="reference_dataset_id")
    p.add_argument("--text-column", dest="text_column")
    p.add_argument("--label-column", dest="label_column")
    p.add_argument("--input-column", dest="input_column")
    p.add_argument("--output-column", dest="output_column")
    p.add_argument("--fail-on", choices=["low", "medium", "high", "critical"], help="exit 1 if risk is at least this level")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_inspect)

    p = sub.add_parser("lineage", help="show downstream artifacts of a dataset")
    p.add_argument("--dataset", required=True)
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_lineage)

    p = sub.add_parser("report", help="print an incident report")
    p.add_argument("--incident", required=True)
    p.add_argument("--format", choices=["markdown", "json"], default="markdown")
    p.add_argument("-o", "--output")
    p.set_defaults(func=cmd_report)

    p = sub.add_parser("ci", help="run configured checks and write a machine-readable report")
    p.add_argument("--config", default=str(CONFIG_FILE))
    p.add_argument("--dataset", action="append", help="override configured datasets")
    p.add_argument("-o", "--output", default="trusttrain-report.json")
    p.set_defaults(func=cmd_ci)
    return parser


def main(argv: list[str] | None = None, stdout: TextIO | None = None) -> int:
    out = _Out(stdout or sys.stdout)
    args = build_parser().parse_args(argv)
    try:
        code: int = args.func(args, out)
    except (LocalDatasetError, TrustTrainError, OSError, json.JSONDecodeError) as exc:
        out.line(f"error: {exc}")
        return 2
    return code


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
