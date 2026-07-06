"""
dcc_parser.py
-------------
Universal calibration certificate XML parser.

Schema-aware: designed around the actual DCC_clamp_meter XML structure:

  <CalibrationCertificate>
    <Organization>
    <CertificateNumber>
    <Instrument>
      <Model>, <ModelNumber>, <SerialNumber>, <Make>
    <EnvironmentalConditions>
      <Temperature>, <RelativeHumidity>
    <Results>
      <Measurement>
        <IndicatedValueA>, <MeasuredValueA>, <ExpandedUncertaintyPercent>

Additional or renamed tags in other schemas are handled via FIELD_CANDIDATES
fallback lists – add new aliases there to support future schemas without
touching any other file.
"""

import xml.etree.ElementTree as ET
from typing import Any


# ---------------------------------------------------------------------------
# Candidate tag lists – ordered: most-specific / most-common first.
# The parser tries each in turn and returns the first non-empty match.
# Add aliases for new schemas at the END of each list.
# ---------------------------------------------------------------------------

FIELD_CANDIDATES: dict[str, list[str]] = {
    "organization": [
        "Organization", "organisation", "Organisation",
        "calibratedFor", "CalibratedFor", "laboratory", "Laboratory", "issuer",
    ],
    "certificate_number": [
        "CertificateNumber", "certificateNumber", "CertNo", "certNo",
        "certificate_number", "certificateNo",
    ],
    "calibration_date": [
        "CalibrationDate", "calibrationDate", "dateOfCalibration",
        "calibration_date", "CalibDate",
    ],
    "date_of_issue": [
        "DateOfIssue", "dateOfIssue", "issueDate", "IssueDate",
        "date_of_issue",
    ],
    "valid_until": [
    "ValidUntil","validUntil","validUntilDate","ExpiryDate",
    ],
    "methodology": [
        "Methodology", "methodology", "CalibrationMethod", "calibrationMethod",
        "procedure", "Procedure", "calibrationProcedure", "CalibrationProcedure",
        "PrincipleMethodology",
    ],
    "traceability": [
        "Traceability", "traceability", "TraceabilityStatement",
        "traceabilityStatement",
    ],
    "standards": [
        "Standards", "standards", "StandardsUsed", "standardsUsed",
    ],
    "remarks": [
        "Remarks", "remarks", "Notes", "notes", "Footer", "footer",
    ],
}

INSTRUMENT_CANDIDATES: dict[str, list[str]] = {
    "model":         ["Model", "model", "InstrumentModel", "instrumentModel"],
    "model_number":  ["ModelNumber", "modelNumber", "ModelNo", "model_number"],
    "serial_number": ["SerialNumber", "serialNumber", "SerialNo", "serial_number"],
    "make":          ["Make", "make", "Manufacturer", "manufacturer"],
    "range":         ["Range", "range", "CurrentRange", "currentRange", "current"],
    "voltage":       ["Voltage", "voltage", "VoltageRange", "voltageRange"],
}

ENV_CANDIDATES: dict[str, list[str]] = {
    "temperature":    ["Temperature", "temperature", "AmbientTemperature",
                       "ambientTemperature", "Temp"],
    "relative_humidity": ["RelativeHumidity", "relativeHumidity", "Humidity",
                          "humidity", "RH"],
}

# Tags that wrap a single measurement row
RESULT_ROW_TAGS = [
    "Measurement", "measurement", "result", "Result",
    "dataPoint", "DataPoint", "row", "Row",
]

# Tags inside each measurement row
RESULT_FIELD_CANDIDATES: dict[str, list[str]] = {
    "indicated_value": [
        "IndicatedValueA", "indicatedValueA", "IndicatedValue",
        "indicatedValue", "indicated_value", "nominalValue", "setPoint", "input",
    ],
    "measured_value": [
        "MeasuredValueA", "measuredValueA", "MeasuredValue",
        "measuredValue", "measured_value", "actualValue", "reference", "output",
    ],
    "uncertainty": [
        "ExpandedUncertaintyPercent", "expandedUncertaintyPercent",
        "ExpandedUncertainty", "expandedUncertainty",
        "uncertainty", "Uncertainty", "expanded_uncertainty", "error",
    ],
}

# Tags that wrap <standards> children
STANDARD_ITEM_TAGS = ["Standard", "standard", "item", "Item", "entry", "Entry"]


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _strip_ns(root: ET.Element) -> None:
    """Remove XML namespace prefixes from all tag names in-place."""
    for elem in root.iter():
        if "}" in elem.tag:
            elem.tag = elem.tag.split("}", 1)[1]


def _find_text(root: ET.Element, candidates: list[str],
               default: str = "N/A") -> str:
    """Return the text of the first matching tag (searched anywhere in tree)."""
    for tag in candidates:
        # Direct child first (faster and avoids deep false matches)
        elem = root.find(tag)
        if elem is None:
            elem = root.find(f".//{tag}")
        if elem is not None:
            val = (elem.text or "").strip()
            if val:
                return val
    return default


def _find_in(parent: ET.Element | None, candidates: list[str],
             default: str = "N/A") -> str:
    """Like _find_text but scoped to *parent* element."""
    if parent is None:
        return default
    for tag in candidates:
        elem = parent.find(tag)
        if elem is not None:
            val = (elem.text or "").strip()
            if val:
                return val
    return default


def _find_parent(root: ET.Element, child_candidates: list[str],
                 parent_candidates: list[str]) -> ET.Element | None:
    """
    Find a container element by trying parent_candidates first,
    then falling back to the root if a child tag is found directly.
    """
    for tag in parent_candidates:
        el = root.find(tag)
        if el is not None:
            return el
    # Fallback: if a child tag exists somewhere, use root as container
    for tag in child_candidates:
        if root.find(f".//{tag}") is not None:
            return root
    return None


def _collect_standards(root: ET.Element) -> list[str]:
    """Collect individual standard descriptions into a list."""
    # Try wrapper element first
    for wrapper_tag in FIELD_CANDIDATES["standards"]:
        wrapper = root.find(wrapper_tag)
        if wrapper is not None:
            items = []
            for item_tag in STANDARD_ITEM_TAGS:
                for el in wrapper.findall(item_tag):
                    txt = (el.text or "").strip()
                    if txt:
                        items.append(txt)
            if items:
                return items
            # Wrapper exists but has no children → use its own text
            txt = (wrapper.text or "").strip()
            if txt:
                return [txt]

    # Flat text tag
    val = _find_text(root, FIELD_CANDIDATES["standards"], default="")
    return [val] if val else ["N/A"]


def _collect_results(root: ET.Element) -> list[dict[str, str]]:
    """Find and parse all measurement rows."""
    rows: list[ET.Element] = []

    # 1. Look inside a <Results> / <results> wrapper
    for wrapper_tag in ("Results", "results", "CalibrationData",
                        "Measurements", "measurements"):
        wrapper = root.find(wrapper_tag)
        if wrapper is not None:
            for row_tag in RESULT_ROW_TAGS:
                found = wrapper.findall(row_tag)
                if found:
                    rows = found
                    break
            if rows:
                break

    # 2. Fallback – search entire tree
    if not rows:
        for row_tag in RESULT_ROW_TAGS:
            rows = root.findall(f".//{row_tag}")
            if rows:
                break

    records = []
    for row in rows:
        record: dict[str, str] = {}
        for field, candidates in RESULT_FIELD_CANDIDATES.items():
            record[field] = _find_in(row, candidates, default="N/A")
        records.append(record)
    return records


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def parse_xml(filepath: str) -> dict[str, Any]:
    """
    Parse a calibration certificate XML file into a normalised dictionary.

    Parameters
    ----------
    filepath : str
        Path to the XML file.

    Returns
    -------
    dict with keys:
        organization, certificate_number, calibration_date, date_of_issue,
        methodology, traceability, remarks, standards (list[str]),
        instrument (dict), environment (dict), results (list[dict])
    """
    try:
        tree = ET.parse(filepath)
        root = tree.getroot()
    except ET.ParseError as exc:
        raise ValueError(f"Cannot parse XML file '{filepath}': {exc}") from exc

    _strip_ns(root)

    # Locate instrument and environment containers (or fall back to root)
    instr_el = _find_parent(root,
                             list(INSTRUMENT_CANDIDATES["model"]),
                             ["Instrument", "instrument", "Device", "device"])
    env_el   = _find_parent(root,
                             list(ENV_CANDIDATES["temperature"]),
                             ["EnvironmentalConditions", "Environment",
                              "environment", "Conditions"])

    data: dict[str, Any] = {
        "organization":      _find_text(root, FIELD_CANDIDATES["organization"]),
        "certificate_number":_find_text(root, FIELD_CANDIDATES["certificate_number"]),
        "calibration_date":  _find_text(root, FIELD_CANDIDATES["calibration_date"]),
        "date_of_issue":     _find_text(root, FIELD_CANDIDATES["date_of_issue"]),
        "valid_until":       _find_text(root, FIELD_CANDIDATES["valid_until"]),
        "methodology":       _find_text(root, FIELD_CANDIDATES["methodology"]),
        "traceability":      _find_text(root, FIELD_CANDIDATES["traceability"]),
        "remarks":           _find_text(root, FIELD_CANDIDATES["remarks"], default=""),
        "standards":         _collect_standards(root),
        "instrument": {
            k: _find_in(instr_el, v, default="")
            for k, v in INSTRUMENT_CANDIDATES.items()
        },
        "environment": {
            "temperature":    _find_in(env_el, ENV_CANDIDATES["temperature"]),
            "relative_humidity": _find_in(env_el, ENV_CANDIDATES["relative_humidity"]),
        },
        "results": _collect_results(root),
    }

    return data


# ---------------------------------------------------------------------------
# CLI smoke-test
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import sys, json
    if len(sys.argv) < 2:
        print("Usage: python dcc_parser.py <input.xml>")
        sys.exit(1)
    print(json.dumps(parse_xml(sys.argv[1]), indent=2))
