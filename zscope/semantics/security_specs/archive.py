"""Canonical JSON and strict XLSX exchange for read-only SecuritySpec review."""

from __future__ import annotations

import json
import re
import zipfile
from pathlib import Path
from typing import Any, Mapping, Optional, Sequence
from xml.etree import ElementTree as ET
from xml.sax.saxutils import escape

from .canonical import canonical_json, content_sha256
from .models import validate_qualification, validate_review_event, validate_security_spec


ARCHIVE_VERSION = "zscope.security-spec-archive.v2"
SHEET_HEADERS = {
    "metadata": ["schema_version", "mode", "store_revision", "bundle_sha256"],
    "specs": ["spec_uid", "revision", "content_sha256", "payload_json"],
    "reviews": ["event_uid", "content_sha256", "payload_json"],
    "qualifications": ["qualification_uid", "content_sha256", "payload_json"],
}


class DuplicateArchiveKeyError(ValueError):
    """Raised when a strict JSON object repeats a key."""


def _strict_object(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateArchiveKeyError("archive_json_duplicate_key:" + key)
        result[key] = value
    return result


def build_archive(
    *,
    specs: Sequence[Mapping[str, Any]],
    reviews: Sequence[Mapping[str, Any]] = (),
    qualifications: Sequence[Mapping[str, Any]] = (),
) -> dict[str, Any]:
    spec_values = [dict(value) for value in specs]
    review_values = [dict(value) for value in reviews]
    qualification_values = [dict(value) for value in qualifications]
    for value in spec_values:
        valid, reason = validate_security_spec(value)
        if not valid:
            raise ValueError("archive_invalid_spec:" + reason)
    for value in review_values:
        valid, reason = validate_review_event(value)
        if not valid:
            raise ValueError("archive_invalid_review:" + reason)
    for value in qualification_values:
        valid, reason = validate_qualification(value)
        if not valid:
            raise ValueError("archive_invalid_qualification:" + reason)
    store_revision = content_sha256(
        {
            "specs": sorted(value["content_sha256"] for value in spec_values),
            "reviews": sorted(value["content_sha256"] for value in review_values),
            "qualifications": sorted(value["content_sha256"] for value in qualification_values),
        }
    )
    body = {
        "schema_version": ARCHIVE_VERSION,
        "mode": "read_only",
        "store_revision": store_revision,
        "specs": sorted(spec_values, key=lambda value: (value["spec_uid"], value["revision"])),
        "reviews": sorted(review_values, key=lambda value: value["event_uid"]),
        "qualifications": sorted(
            qualification_values, key=lambda value: value["qualification_uid"]
        ),
    }
    return {**body, "bundle_sha256": content_sha256(body)}


def validate_archive(
    raw: Mapping[str, Any], *, expected_store_revision: str = ""
) -> tuple[bool, str]:
    expected_keys = {
        "schema_version",
        "mode",
        "store_revision",
        "specs",
        "reviews",
        "qualifications",
        "bundle_sha256",
    }
    if set(raw) != expected_keys:
        return False, "archive_schema_keys_mismatch"
    if raw.get("schema_version") != ARCHIVE_VERSION or raw.get("mode") != "read_only":
        return False, "unsupported_archive_version"
    body = dict(raw)
    supplied = str(body.pop("bundle_sha256", ""))
    if content_sha256(body) != supplied:
        return False, "archive_bundle_hash_mismatch"
    if expected_store_revision and raw.get("store_revision") != expected_store_revision:
        return False, "archive_store_revision_stale"
    collections = {
        "specs": ("spec_uid", "revision", validate_security_spec),
        "reviews": ("event_uid", "content_sha256", validate_review_event),
        "qualifications": (
            "qualification_uid",
            "content_sha256",
            validate_qualification,
        ),
    }
    for name, (first, second, validator) in collections.items():
        values = raw.get(name)
        if not isinstance(values, list):
            return False, f"archive_{name}_not_array"
        identities = []
        for value in values:
            if not isinstance(value, Mapping):
                return False, f"archive_{name}_item_not_object"
            valid, reason = validator(value)
            if not valid:
                return False, f"archive_{name}_invalid:{reason}"
            identities.append((str(value.get(first)), str(value.get(second))))
        if len(identities) != len(set(identities)):
            return False, f"archive_{name}_duplicate_identity"
    valid, reason = _validate_review_chain(raw)
    if not valid:
        return False, reason
    return True, "ok"


def _validate_review_chain(raw: Mapping[str, Any]) -> tuple[bool, str]:
    specs = list(raw.get("specs") or [])
    reviews = list(raw.get("reviews") or [])
    spec_hashes = {
        (str(value.get("spec_uid")), int(value.get("revision", 0))): str(
            value.get("content_sha256") or ""
        )
        for value in specs
        if isinstance(value, Mapping)
    }
    by_spec: dict[str, list[Mapping[str, Any]]] = {}
    for event in reviews:
        if not isinstance(event, Mapping):
            return False, "archive_review_item_not_object"
        key = (str(event.get("spec_uid")), int(event.get("spec_revision", 0)))
        before = str(event.get("before_spec_sha256") or "")
        if spec_hashes.get(key) != before:
            return False, "archive_review_spec_binding_mismatch"
        by_spec.setdefault(key[0], []).append(event)
    for events in by_spec.values():
        by_hash = {str(value["content_sha256"]): value for value in events}
        if len(by_hash) != len(events):
            return False, "archive_review_chain_duplicate_hash"
        roots = [
            value for value in events if str(value.get("previous_event_sha256") or "") == "0" * 64
        ]
        if len(roots) != 1:
            return False, "archive_review_chain_root_count"
        children: dict[str, list[Mapping[str, Any]]] = {}
        for value in events:
            previous = str(value.get("previous_event_sha256") or "")
            if previous == "0" * 64:
                continue
            if previous not in by_hash:
                return False, "archive_review_chain_reference_missing"
            children.setdefault(previous, []).append(value)
        if any(len(values) != 1 for values in children.values()):
            return False, "archive_review_chain_branching"
        visited: set[str] = set()
        current: Optional[Mapping[str, Any]] = roots[0]
        while current is not None:
            digest = str(current["content_sha256"])
            if digest in visited:
                return False, "archive_review_chain_cycle"
            visited.add(digest)
            next_values = children.get(digest) or []
            current = next_values[0] if next_values else None
        if len(visited) != len(events):
            return False, "archive_review_chain_disconnected"
    return True, "ok"


def archive_to_json_bytes(archive: Mapping[str, Any]) -> bytes:
    valid, reason = validate_archive(archive)
    if not valid:
        raise ValueError(reason)
    return (canonical_json(archive) + "\n").encode("utf-8")


def archive_from_json_bytes(data: bytes, *, expected_store_revision: str = "") -> dict[str, Any]:
    raw = json.loads(data.decode("utf-8"), object_pairs_hook=_strict_object)
    if not isinstance(raw, dict):
        raise ValueError("archive_json_not_object")
    valid, reason = validate_archive(raw, expected_store_revision=expected_store_revision)
    if not valid:
        raise ValueError(reason)
    return raw


def archive_to_xlsx(path: Path, archive: Mapping[str, Any]) -> None:
    valid, reason = validate_archive(archive)
    if not valid:
        raise ValueError(reason)
    rows = {
        "metadata": [
            {
                "schema_version": str(archive["schema_version"]),
                "mode": str(archive["mode"]),
                "store_revision": str(archive["store_revision"]),
                "bundle_sha256": str(archive["bundle_sha256"]),
            }
        ],
        "specs": [
            {
                "spec_uid": str(value["spec_uid"]),
                "revision": str(value["revision"]),
                "content_sha256": str(value["content_sha256"]),
                "payload_json": canonical_json(value),
            }
            for value in archive["specs"]
        ],
        "reviews": [
            {
                "event_uid": str(value["event_uid"]),
                "content_sha256": str(value["content_sha256"]),
                "payload_json": canonical_json(value),
            }
            for value in archive["reviews"]
        ],
        "qualifications": [
            {
                "qualification_uid": str(value["qualification_uid"]),
                "content_sha256": str(value["content_sha256"]),
                "payload_json": canonical_json(value),
            }
            for value in archive["qualifications"]
        ],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    sheet_names = list(SHEET_HEADERS)
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive_file:
        archive_file.writestr("[Content_Types].xml", _content_types(sheet_names))
        archive_file.writestr("_rels/.rels", _root_relationships())
        archive_file.writestr("xl/workbook.xml", _workbook_xml(sheet_names))
        archive_file.writestr("xl/_rels/workbook.xml.rels", _workbook_rels(sheet_names))
        archive_file.writestr("xl/styles.xml", _styles_xml())
        for index, name in enumerate(sheet_names, start=1):
            archive_file.writestr(
                f"xl/worksheets/sheet{index}.xml", _worksheet_xml(name, rows[name])
            )


def archive_from_xlsx(path: Path, *, expected_store_revision: str = "") -> dict[str, Any]:
    with zipfile.ZipFile(path) as archive_file:
        workbook = ET.fromstring(archive_file.read("xl/workbook.xml"))
        relationships = _read_relationships(archive_file)
        namespace = {
            "m": "http://schemas.openxmlformats.org/spreadsheetml/2006/main",
            "r": "http://schemas.openxmlformats.org/officeDocument/2006/relationships",
        }
        raw_sheets = workbook.findall(".//m:sheet", namespace)
        names = [element.attrib.get("name", "") for element in raw_sheets]
        if names != list(SHEET_HEADERS):
            raise ValueError("archive_xlsx_sheet_set_or_order_mismatch")
        parsed: dict[str, list[dict[str, str]]] = {}
        for element in raw_sheets:
            name = element.attrib.get("name", "")
            rel_id = element.attrib.get(f"{{{namespace['r']}}}id", "")
            target = relationships.get(rel_id, "").lstrip("/")
            sheet_path = target if target.startswith("xl/") else "xl/" + target
            matrix = _sheet_matrix(archive_file.read(sheet_path))
            if not matrix or matrix[0] != SHEET_HEADERS[name]:
                raise ValueError(f"archive_xlsx_headers_mismatch:{name}")
            parsed[name] = [
                {
                    header: values[index] if index < len(values) else ""
                    for index, header in enumerate(matrix[0])
                }
                for values in matrix[1:]
                if any(str(value).strip() for value in values)
            ]
    metadata = parsed["metadata"]
    if len(metadata) != 1:
        raise ValueError("archive_xlsx_metadata_row_required")
    raw = {
        "schema_version": metadata[0]["schema_version"],
        "mode": metadata[0]["mode"],
        "store_revision": metadata[0]["store_revision"],
        "specs": _payload_rows(parsed["specs"], "spec_uid", "revision"),
        "reviews": _payload_rows(parsed["reviews"], "event_uid", "content_sha256"),
        "qualifications": _payload_rows(
            parsed["qualifications"], "qualification_uid", "content_sha256"
        ),
        "bundle_sha256": metadata[0]["bundle_sha256"],
    }
    valid, reason = validate_archive(raw, expected_store_revision=expected_store_revision)
    if not valid:
        raise ValueError(reason)
    return raw


def _payload_rows(rows: Sequence[Mapping[str, str]], first: str, second: str) -> list[Any]:
    values = []
    for row in rows:
        payload = json.loads(str(row.get("payload_json") or ""), object_pairs_hook=_strict_object)
        if not isinstance(payload, dict):
            raise ValueError("archive_xlsx_payload_not_object")
        if str(payload.get(first)) != str(row.get(first)) or str(payload.get(second)) != str(
            row.get(second)
        ):
            raise ValueError("archive_xlsx_identity_mismatch")
        if str(payload.get("content_sha256")) != str(row.get("content_sha256")):
            raise ValueError("archive_xlsx_content_hash_mismatch")
        values.append(payload)
    return values


def _column_name(index: int) -> str:
    value = ""
    while index:
        index, remainder = divmod(index - 1, 26)
        value = chr(65 + remainder) + value
    return value


def _worksheet_xml(sheet: str, rows: Sequence[Mapping[str, str]]) -> str:
    headers = SHEET_HEADERS[sheet]
    all_rows = [dict(zip(headers, headers))] + [dict(value) for value in rows]
    xml_rows = []
    for row_index, row in enumerate(all_rows, start=1):
        cells = []
        for column_index, header in enumerate(headers, start=1):
            reference = f"{_column_name(column_index)}{row_index}"
            value = escape(str(row.get(header, "")))
            cells.append(f'<c r="{reference}" t="inlineStr"><is><t>{value}</t></is></c>')
        xml_rows.append(f'<row r="{row_index}">{"".join(cells)}</row>')
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        f'<dimension ref="A1:{_column_name(len(headers))}{len(all_rows)}"/>'
        f'<sheetData>{"".join(xml_rows)}</sheetData></worksheet>'
    )


def _sheet_matrix(xml_data: bytes) -> list[list[str]]:
    root = ET.fromstring(xml_data)
    namespace = {"m": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}
    matrix = []
    for row in root.findall(".//m:row", namespace):
        values: dict[int, str] = {}
        for cell in row.findall("m:c", namespace):
            reference = cell.attrib.get("r", "")
            letters = re.sub(r"[^A-Z]", "", reference.upper())
            index = 0
            for letter in letters:
                index = index * 26 + ord(letter) - 64
            if cell.attrib.get("t") == "inlineStr":
                value = "".join(node.text or "" for node in cell.findall(".//m:t", namespace))
            else:
                node = cell.find("m:v", namespace)
                value = str(node.text or "") if node is not None else ""
            values[index or 1] = value
        if values:
            matrix.append([values.get(index, "") for index in range(1, max(values) + 1)])
    return matrix


def _read_relationships(archive_file: zipfile.ZipFile) -> dict[str, str]:
    root = ET.fromstring(archive_file.read("xl/_rels/workbook.xml.rels"))
    namespace = {"r": "http://schemas.openxmlformats.org/package/2006/relationships"}
    return {
        node.attrib.get("Id", ""): node.attrib.get("Target", "")
        for node in root.findall("r:Relationship", namespace)
    }


def _content_types(names: Sequence[str]) -> str:
    sheets = "".join(
        f'<Override PartName="/xl/worksheets/sheet{index}.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
        for index, _ in enumerate(names, start=1)
    )
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
        '<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>'
        f"{sheets}</Types>"
    )


def _root_relationships() -> str:
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>'
        "</Relationships>"
    )


def _workbook_xml(names: Sequence[str]) -> str:
    sheets = "".join(
        f'<sheet name="{escape(name)}" sheetId="{index}" r:id="rId{index}"/>'
        for index, name in enumerate(names, start=1)
    )
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
        f"<sheets>{sheets}</sheets></workbook>"
    )


def _workbook_rels(names: Sequence[str]) -> str:
    relationships = "".join(
        f'<Relationship Id="rId{index}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet{index}.xml"/>'
        for index, _ in enumerate(names, start=1)
    )
    relationships += (
        f'<Relationship Id="rId{len(names) + 1}" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" '
        'Target="styles.xml"/>'
    )
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        f"{relationships}</Relationships>"
    )


def _styles_xml() -> str:
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        '<fonts count="1"><font><sz val="11"/><name val="Calibri"/></font></fonts>'
        '<fills count="1"><fill><patternFill patternType="none"/></fill></fills>'
        '<borders count="1"><border/></borders><cellStyleXfs count="1"><xf/></cellStyleXfs>'
        '<cellXfs count="1"><xf xfId="0"/></cellXfs></styleSheet>'
    )
