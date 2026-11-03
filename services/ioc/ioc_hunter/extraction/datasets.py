"""Read existing report datasets without modifying them."""
import csv
from pathlib import Path
from ..config import DEFAULT_DATASET, DATASET_DIRECTORY

def load_reports(path: Path) -> list[dict]:
    """Read CSV or the first Excel worksheet; never modify the source file."""
    if path.suffix.lower() == ".csv":
        # CTI reports can exceed the standard csv module's field-size limit.
        csv.field_size_limit(100_000_000)
        with path.open(encoding="utf-8-sig", newline="") as stream:
            reader = csv.DictReader(stream)
            if not reader.fieldnames or "cti_content" not in reader.fieldnames:
                raise ValueError("The dataset must contain a cti_content column.")
            return list(reader)
    if path.suffix.lower() == ".xlsx":
        from openpyxl import load_workbook

        workbook = load_workbook(path, read_only=True, data_only=True)
        try:
            rows = workbook.worksheets[0].iter_rows(values_only=True)
            headers = next(rows, ())
            if "cti_content" not in headers:
                raise ValueError("The first worksheet must contain a cti_content column.")
            return [dict(zip(headers, row)) for row in rows]
        finally:
            workbook.close()
    raise ValueError("Choose a .csv or .xlsx dataset.")
