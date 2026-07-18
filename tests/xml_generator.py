"""
tests/xml_generator.py

Builds synthetic <CalibrationCertificate> XML documents matching the flat
schema core/xml_parser.py expects (the same schema as
samples/DCC_clamp_meter1.xml). Used by the comprehensive test suite to
generate a wide variety of file sizes and field values without depending
on a fixed set of sample files.
"""

import random

DEFAULT_ORGANIZATION = "CSIR-National Physical Laboratory"
DEFAULT_CERTIFICATE_NUMBER = "N25040063/D2.02/C-029"
DEFAULT_VALID_UNTIL = "2032-09-15"
DEFAULT_MODEL = "True RMS Clamp Meter"
DEFAULT_MODEL_NUMBER = "376FC"
DEFAULT_SERIAL_NUMBER = "62120296WS"
DEFAULT_MAKE = "FLUKE, USA"
DEFAULT_TEMPERATURE = "25 ± 2 °C"
DEFAULT_RELATIVE_HUMIDITY = "50 ± 10 %"


def default_rows(num_rows: int, seed: int | None = None) -> list[tuple[str, str, str]]:
    """Generate realistic (indicated, measured, uncertainty) triples."""
    rng = random.Random(seed)
    rows = []
    base = 10.0
    for i in range(num_rows):
        indicated = base * (i + 1)
        drift = rng.uniform(-0.015, 0.015)
        measured = indicated * (1 + drift)
        uncertainty = round(rng.uniform(0.15, 2.0), 2)
        rows.append((f"{indicated:.1f}", f"{measured:.1f}", f"±{uncertainty}"))
    return rows


def build_flat_xml(
    organization: str = DEFAULT_ORGANIZATION,
    certificate_number: str = DEFAULT_CERTIFICATE_NUMBER,
    valid_until: str = DEFAULT_VALID_UNTIL,
    model: str = DEFAULT_MODEL,
    model_number: str = DEFAULT_MODEL_NUMBER,
    serial_number: str = DEFAULT_SERIAL_NUMBER,
    make: str = DEFAULT_MAKE,
    temperature: str = DEFAULT_TEMPERATURE,
    relative_humidity: str = DEFAULT_RELATIVE_HUMIDITY,
    rows: list[tuple[str, str, str]] | None = None,
    num_rows: int = 6,
    seed: int | None = None,
    omit_fields: set[str] | None = None,
) -> str:
    """
    Build a <CalibrationCertificate> XML document as a string.

    omit_fields, if given, drops those tags entirely (rather than giving
    them a wrong value) — used to synthesize the "missing field" tamper
    scenario, where a field is absent from the document altogether.
    Recognised names: Organization, CertificateNumber, ValidUntil, Model,
    ModelNumber, SerialNumber, Make, Temperature, RelativeHumidity.
    """
    if rows is None:
        rows = default_rows(num_rows, seed=seed)

    omit = omit_fields or set()

    def want(tag: str) -> bool:
        return tag not in omit

    lines = ["<?xml version='1.0' encoding='utf-8'?>", "<CalibrationCertificate>"]

    if want("Organization"):
        lines.append(f"    <Organization>{organization}</Organization>")
    if want("CertificateNumber"):
        lines.append(f"    <CertificateNumber>{certificate_number}</CertificateNumber>")
    if want("ValidUntil"):
        lines.append(f"    <ValidUntil>{valid_until}</ValidUntil>")

    lines.append("    <Instrument>")
    if want("Model"):
        lines.append(f"        <Model>{model}</Model>")
    if want("ModelNumber"):
        lines.append(f"        <ModelNumber>{model_number}</ModelNumber>")
    if want("SerialNumber"):
        lines.append(f"        <SerialNumber>{serial_number}</SerialNumber>")
    if want("Make"):
        lines.append(f"        <Make>{make}</Make>")
    lines.append("    </Instrument>")

    lines.append("    <EnvironmentalConditions>")
    if want("Temperature"):
        lines.append(f"        <Temperature>{temperature}</Temperature>")
    if want("RelativeHumidity"):
        lines.append(f"        <RelativeHumidity>{relative_humidity}</RelativeHumidity>")
    lines.append("    </EnvironmentalConditions>")

    lines.append("    <Results>")
    for indicated, measured, uncertainty in rows:
        lines.append("        <Measurement>")
        lines.append(f"            <IndicatedValueA>{indicated}</IndicatedValueA>")
        lines.append(f"            <MeasuredValueA>{measured}</MeasuredValueA>")
        lines.append(f"            <ExpandedUncertaintyPercent>{uncertainty}</ExpandedUncertaintyPercent>")
        lines.append("        </Measurement>")
    lines.append("    </Results>")

    lines.append("</CalibrationCertificate>")
    return "\n".join(lines)
