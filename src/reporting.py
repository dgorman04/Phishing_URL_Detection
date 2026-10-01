"""Helpers for writing generated sections into the markdown reports."""
from pathlib import Path


def splice_section(path: Path, key: str, text: str) -> None:
    """Insert or replace a generated section in a markdown report.

    The section sits between <!-- BEGIN key --> and <!-- END key --> markers, so rerunning a
    step replaces its section instead of appending a second copy.
    """
    begin, end = f"<!-- BEGIN {key} -->", f"<!-- END {key} -->"
    block = f"{begin}\n{text.strip()}\n{end}\n"
    doc = path.read_text(encoding="utf-8") if path.exists() else ""
    if begin in doc and end in doc:
        before, rest = doc.split(begin, 1)
        after = rest.split(end, 1)[1].lstrip("\n")
        doc = before + block + ("\n" + after if after else "")
    else:
        doc = doc.rstrip("\n") + "\n\n" + block
    path.write_text(doc, encoding="utf-8")
