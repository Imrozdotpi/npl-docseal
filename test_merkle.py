from core.xml_parser import parse_xml
from core.merkle import build_merkle_tree

parsed = parse_xml("samples/DCC_clamp_meter1.xml")
result = build_merkle_tree(parsed)

print("ROOT:", result["root"])
print("FIELD COUNT:", len(result["fields"]))
print("LEAF COUNT:", len(result["leaves"]))
print("TREE DEPTH:", len(result["tree"]))

print("\nFIELD HASHES\n")

for name, value in result["field_hashes"].items():
    print(f"{name:35} {value[:16]}...")

print("\nMERKLE TREE\n")

for level, nodes in enumerate(result["tree"]):
    print(f"Level {level}: {len(nodes)} nodes")