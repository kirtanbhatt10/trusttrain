"""Safe, read-only loading of supported dataset formats into pandas.

No format handled here can execute code: CSV/TXT are parsed as text, JSON/JSONL
with the standard ``json`` module, and Parquet with PyArrow. Pickle-based
formats are deliberately unsupported.
"""

from __future__ import annotations

import io
import json
from pathlib import Path

import pandas as pd
import pyarrow.parquet as pq

SUPPORTED_FORMATS = {"csv", "json", "jsonl", "parquet", "txt"}
_EXTENSION_MAP = {".csv": "csv", ".json": "json", ".jsonl": "jsonl", ".ndjson": "jsonl", ".parquet": "parquet", ".txt": "txt"}


class DatasetFormatError(ValueError):
    """Raised when a file is not a valid instance of its declared format."""


def detect_format(filename: str) -> str:
    fmt = _EXTENSION_MAP.get(Path(filename).suffix.lower())
    if fmt is None:
        raise DatasetFormatError(f"Unsupported file type: {Path(filename).suffix or '(none)'}")
    return fmt


def load_dataframe(path: Path, fmt: str, max_rows: int, max_cell_chars: int | None = None) -> pd.DataFrame:
    """Load ``path`` as a DataFrame of at most ``max_rows`` rows.

    When ``max_cell_chars`` is set, any text cell longer than that is rejected
    (very long cells make the text detectors slow and are rarely legitimate).

    Raises ``DatasetFormatError`` if the content is malformed or exceeds limits.
    """
    if fmt not in SUPPORTED_FORMATS:
        raise DatasetFormatError(f"Unsupported format: {fmt}")
    try:
        if fmt == "parquet":
            with path.open("rb") as fh:
                if fh.read(4) != b"PAR1":
                    raise DatasetFormatError("File is not a Parquet file (missing PAR1 magic)")
            meta = pq.ParquetFile(path).metadata
            if meta.num_rows > max_rows:
                raise DatasetFormatError(f"Dataset has {meta.num_rows} rows; limit is {max_rows}")
            df = pq.read_table(path).to_pandas()
        elif fmt == "csv":
            df = pd.read_csv(io.StringIO(_read_text(path)), nrows=max_rows + 1, dtype_backend="numpy_nullable")
        elif fmt == "txt":
            lines = [ln for ln in _read_text(path).splitlines() if ln.strip()]
            df = pd.DataFrame({"text": lines})
        elif fmt == "json":
            data = json.loads(_read_text(path))
            if isinstance(data, dict):
                # Accept {"data": [...]} style wrappers.
                candidates = [v for v in data.values() if isinstance(v, list)]
                if len(candidates) != 1:
                    raise DatasetFormatError("JSON object must contain exactly one list of records")
                data = candidates[0]
            if not isinstance(data, list) or not all(isinstance(r, dict) for r in data):
                raise DatasetFormatError("JSON dataset must be a list of objects")
            df = pd.DataFrame.from_records(data)
        else:  # jsonl
            records = []
            for lineno, line in enumerate(_read_text(path).splitlines(), start=1):
                if not line.strip():
                    continue
                obj = json.loads(line)
                if not isinstance(obj, dict):
                    raise DatasetFormatError(f"JSONL line {lineno} is not an object")
                records.append(obj)
                if len(records) > max_rows:
                    break
            df = pd.DataFrame.from_records(records)
    except DatasetFormatError:
        raise
    except (json.JSONDecodeError, UnicodeDecodeError, pd.errors.ParserError, pd.errors.EmptyDataError, OSError) as exc:
        raise DatasetFormatError(f"Could not parse {fmt} file: {exc}") from exc
    except Exception as exc:  # pyarrow raises a variety of error types
        raise DatasetFormatError(f"Could not parse {fmt} file: {type(exc).__name__}") from exc

    if len(df) > max_rows:
        raise DatasetFormatError(f"Dataset exceeds the {max_rows}-row processing limit")
    if df.empty:
        raise DatasetFormatError("Dataset contains no rows")
    df.columns = [str(c) for c in df.columns]
    if max_cell_chars is not None:
        _check_cell_lengths(df, max_cell_chars)
    return df


def _check_cell_lengths(df: pd.DataFrame, limit: int) -> None:
    for column in df.columns:
        series = df[column]
        if series.dtype != object and not pd.api.types.is_string_dtype(series):
            continue
        lengths = series.map(lambda v: len(v) if isinstance(v, str) else 0)
        longest = int(lengths.max()) if len(lengths) else 0
        if longest > limit:
            row = int(lengths.to_numpy().argmax())
            raise DatasetFormatError(f"Column '{column}' row {row} has {longest} characters; the per-cell limit is {limit}")


def _read_text(path: Path) -> str:
    raw = path.read_bytes()
    if b"\x00" in raw[:8192]:
        raise DatasetFormatError("Binary content found in a text-based dataset")
    return raw.decode("utf-8-sig")
