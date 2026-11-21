#!/usr/bin/env python3
"""Render the standalone ProofGate report template with the sample JSON."""
import json
import re
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape


ROOT = Path(__file__).resolve().parent
env = Environment(
    loader=FileSystemLoader(ROOT),
    autoescape=select_autoescape(enabled_extensions=("html", "xml")),
)
template = env.get_template("report.html")
data = json.loads((ROOT / "sample_report.json").read_text(encoding="utf-8"))
# Defense in depth for report values: redact canary suffixes before rendering.
def mask_canaries(value):
    if isinstance(value, dict):
        return {key: mask_canaries(item) for key, item in value.items()}
    if isinstance(value, list):
        return [mask_canaries(item) for item in value]
    if isinstance(value, str):
        return re.sub(r"PGCANARY_A_[^\s\"'<>]+", "PGCANARY_A_«masked»", value)
    return value

data = mask_canaries(data)
data.setdefault("filters", {}).setdefault("layers", sorted({str(f["layer"]) for f in data.get("findings", [])}))
data.setdefault("blind_spots", [
    "Multi-step flows", "Routes with complex request bodies", "Non-id lookups such as ?email=",
    "Storage buckets", "Edge functions", "Business logic", "Payments",
])
output = template.render(**data)
destination = ROOT / "sample_report.html"
destination.write_text(output, encoding="utf-8")
print(f"Rendered {destination}")
