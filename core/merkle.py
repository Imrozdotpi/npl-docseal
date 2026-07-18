import hashlib
import json


def _sha256(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def _flatten_fields(parsed: dict) -> dict:
    """
    Takes the dict from parse_xml() and returns a flat ordered dict
    of field_name -> value strings. Order is fixed and deterministic:
    this is critical, same XML must always produce same Merkle tree.
    """
    fields = {}

    # Top-level fields
    fields["organization"]      = str(parsed.get("organization", ""))
    fields["certificate_number"]= str(parsed.get("certificate_number", ""))
    fields["calibration_date"]  = str(parsed.get("calibration_date", ""))
    fields["date_of_issue"]     = str(parsed.get("date_of_issue", ""))
    fields["valid_until"]       = str(parsed.get("valid_until", ""))
    fields["methodology"]       = str(parsed.get("methodology", ""))
    fields["traceability"]      = str(parsed.get("traceability", ""))

    # Instrument fields
    inst = parsed.get("instrument", {})
    fields["instrument_model"]        = str(inst.get("model", ""))
    fields["instrument_model_number"] = str(inst.get("model_number", ""))
    fields["instrument_serial_number"]= str(inst.get("serial_number", ""))
    fields["instrument_make"]         = str(inst.get("make", ""))

    # Environment fields
    env = parsed.get("environment", {})
    fields["environment_temperature"]      = str(env.get("temperature", ""))
    fields["environment_relative_humidity"]= str(env.get("relative_humidity", ""))

    # Measurement results, each row becomes 3 named fields
    results = parsed.get("results", [])
    for i, row in enumerate(results):
        fields[f"result_{i+1}_indicated"] = str(row.get("indicated_value", ""))
        fields[f"result_{i+1}_measured"]  = str(row.get("measured_value", ""))
        fields[f"result_{i+1}_uncertainty"]= str(row.get("uncertainty", ""))

    return fields


def _build_tree(leaf_hashes: list) -> list:
    """
    Builds a Merkle tree from a list of leaf hashes.
    Returns list of levels, bottom (leaves) to top (root).
    If odd number of nodes, duplicates the last one.
    """
    if not leaf_hashes:
        return []

    levels = [leaf_hashes]
    current = leaf_hashes

    while len(current) > 1:
        next_level = []
        # pair up nodes; duplicate last if odd
        if len(current) % 2 == 1:
            current = current + [current[-1]]
        for i in range(0, len(current), 2):
            combined = current[i] + current[i + 1]
            next_level.append(_sha256(combined))
        levels.append(next_level)
        current = next_level

    return levels


def build_merkle_tree(parsed: dict) -> dict:
    """
    Main function. Takes the dict from parse_xml(), returns:
    {
        "fields":       {field_name: value},
        "field_hashes": {field_name: sha256_hex},
        "leaves":       [sha256_hex, ...],   # ordered list of leaf hashes
        "tree":         [[level0], [level1], ...],
        "root":         sha256_hex            # the Merkle root: this gets signed
    }
    """
    fields = _flatten_fields(parsed)

    # Hash each field as "field_name:value" to prevent cross-field substitution
    field_hashes = {
        name: _sha256(f"{name}:{value}")
        for name, value in fields.items()
    }

    leaves = list(field_hashes.values())
    tree   = _build_tree(leaves)
    root   = tree[-1][0] if tree else _sha256("")

    return {
        "fields":       fields,
        "field_hashes": field_hashes,
        "leaves":       leaves,
        "tree":         tree,
        "root":         root
    }


def verify_field(field_name: str, field_value: str, stored_hash: str) -> bool:
    """
    Checks if a single field matches its stored hash.
    Used during verification to identify which fields were tampered.
    """
    recomputed = _sha256(f"{field_name}:{field_value}")
    return recomputed == stored_hash


def compare_trees(original_proof: dict, current_parsed: dict) -> dict:
    """
    Takes the stored merkle_proof.json and the freshly parsed XML dict.
    Returns a field-by-field report of intact vs tampered fields.
    """
    current_fields  = _flatten_fields(current_parsed)
    stored_hashes   = original_proof["field_hashes"]
    stored_root     = original_proof["root"]

    report = {}
    for field_name, current_value in current_fields.items():
        stored_hash = stored_hashes.get(field_name)
        if stored_hash is None:
            report[field_name] = {"status": "MISSING", "value": current_value}
        elif verify_field(field_name, current_value, stored_hash):
            report[field_name] = {"status": "INTACT", "value": current_value}
        else:
            report[field_name] = {"status": "TAMPERED", "value": current_value}

    # Recompute root from current fields to confirm overall integrity
    current_tree = build_merkle_tree(current_parsed)
    root_matches = current_tree["root"] == stored_root

    return {
        "root_matches": root_matches,
        "fields": report
    }