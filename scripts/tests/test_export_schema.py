"""Checks the exported model against the schema the repository publishes.

`threatmodeller export --format json` writes the shape
`docs/threatmodel-export.schema.json` states, and `ThreatModelKit/Tests/Goldens`
holds one written file. A change to the export that nobody wrote into the
schema fails here.

The check reads the part of JSON Schema the file uses — type, required,
properties, additionalProperties, items, enum, const, minimum, maximum and a
reference into $defs — so CI needs no package for it.
"""

import json
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
SCHEMA = ROOT / "docs" / "threatmodel-export.schema.json"
GOLDENS = ROOT / "ThreatModelKit" / "Tests" / "Goldens"

TYPES = {
    "object": dict,
    "array": list,
    "string": str,
    "integer": int,
    "boolean": bool,
}


def type_matches(value, wanted):
    if wanted == "null":
        return value is None
    if wanted == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if wanted == "boolean":
        return isinstance(value, bool)
    return isinstance(value, TYPES[wanted])


def check(value, schema, root, where, faults):
    if "$ref" in schema:
        name = schema["$ref"].split("/")[-1]
        check(value, root["$defs"][name], root, where, faults)
        return

    wanted = schema.get("type")
    if wanted is not None:
        allowed = wanted if isinstance(wanted, list) else [wanted]
        if not any(type_matches(value, one) for one in allowed):
            faults.append(f"{where} is {type(value).__name__}, not {'|'.join(allowed)}")
            return

    if "const" in schema and value != schema["const"]:
        faults.append(f"{where} is {value!r}, not {schema['const']!r}")
    if "enum" in schema and value not in schema["enum"]:
        faults.append(f"{where} is {value!r}, which the schema does not hold")
    if "minimum" in schema and isinstance(value, int) and value < schema["minimum"]:
        faults.append(f"{where} is {value}, below {schema['minimum']}")
    if "maximum" in schema and isinstance(value, int) and value > schema["maximum"]:
        faults.append(f"{where} is {value}, above {schema['maximum']}")

    if isinstance(value, dict):
        for key in schema.get("required", []):
            if key not in value:
                faults.append(f"{where} states no {key}")
        properties = schema.get("properties", {})
        if schema.get("additionalProperties") is False:
            for key in value:
                if key not in properties:
                    faults.append(f"{where} holds {key}, which the schema does not state")
        for key, inner in properties.items():
            if key in value:
                check(value[key], inner, root, f"{where}.{key}", faults)

    if isinstance(value, list) and "items" in schema:
        for index, item in enumerate(value):
            check(item, schema["items"], root, f"{where}[{index}]", faults)


class ExportSchemaTests(unittest.TestCase):
    def setUp(self):
        self.schema = json.loads(SCHEMA.read_text())

    def test_the_golden_export_keeps_the_published_schema(self):
        document = json.loads((GOLDENS / "payments-export.json").read_text())
        faults = []
        check(document, self.schema, self.schema, "the export", faults)
        self.assertEqual([], faults)

    def test_the_golden_export_states_the_schema_version(self):
        document = json.loads((GOLDENS / "payments-export.json").read_text())
        self.assertEqual(
            self.schema["properties"]["schemaVersion"]["const"],
            document["schemaVersion"],
        )

    def test_the_open_threat_model_export_states_its_version(self):
        document = json.loads((GOLDENS / "payments-export.otm.json").read_text())
        self.assertIn("otmVersion", document)
        for key in ["project", "components", "dataflows", "threats", "mitigations"]:
            self.assertIn(key, document)


if __name__ == "__main__":
    unittest.main()
