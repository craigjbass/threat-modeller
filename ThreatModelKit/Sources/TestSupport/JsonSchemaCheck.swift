import Foundation

/// Reads a JSON value against the part of JSON Schema the repository's own
/// schema files use: `$ref` into `$defs`, `type`, `required`, `properties`,
/// `additionalProperties`, `items`, `enum`, `const`, `minimum` and `maximum`.
///
/// `scripts/tests/test_export_schema.py` reads the golden file the same way,
/// so a test here and the check in CI state one rule.
public enum JsonSchemaCheck {
    /// `docs/threatmodel-export.schema.json`, as a dictionary.
    public static func exportSchema() throws -> [String: Any] {
        let path = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .appendingPathComponent("docs")
            .appendingPathComponent("threatmodel-export.schema.json")
        let data = try Data(contentsOf: path)
        guard let schema = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw JsonSchemaFault.notAnObject(path.path)
        }
        return schema
    }

    /// Every way the value departs from the schema. Empty when it matches.
    public static func faults(in value: Any, against schema: [String: Any]) -> [String] {
        var faults: [String] = []
        check(value, schema, schema, "the file", &faults)
        return faults
    }

    private static func check(
        _ value: Any,
        _ schema: [String: Any],
        _ root: [String: Any],
        _ where: String,
        _ faults: inout [String]
    ) {
        if let reference = schema["$ref"] as? String {
            let name = String(reference.split(separator: "/").last ?? "")
            let defs = root["$defs"] as? [String: Any] ?? [:]
            guard let target = defs[name] as? [String: Any] else {
                faults.append("\(`where`) names $defs/\(name), which the schema does not hold")
                return
            }
            check(value, target, root, `where`, &faults)
            return
        }

        if let wanted = schema["type"] {
            let allowed = wanted as? [String] ?? [wanted as? String ?? ""]
            guard allowed.contains(where: { matches(value, $0) }) else {
                faults.append("\(`where`) is not \(allowed.joined(separator: "|"))")
                return
            }
        }

        if let constant = schema["const"], equal(value, constant) == false {
            faults.append("\(`where`) is not the constant the schema states")
        }
        if let choices = schema["enum"] as? [Any],
           choices.contains(where: { equal(value, $0) }) == false {
            faults.append("\(`where`) is \(value), which the schema does not hold")
        }
        if let lowest = schema["minimum"] as? Int, let number = value as? Int, number < lowest {
            faults.append("\(`where`) is \(number), below \(lowest)")
        }
        if let highest = schema["maximum"] as? Int, let number = value as? Int, number > highest {
            faults.append("\(`where`) is \(number), above \(highest)")
        }

        if let object = value as? [String: Any] {
            for name in schema["required"] as? [String] ?? [] where object[name] == nil {
                faults.append("\(`where`) states no \(name)")
            }
            let properties = schema["properties"] as? [String: Any] ?? [:]
            if schema["additionalProperties"] as? Bool == false {
                for name in object.keys where properties[name] == nil {
                    faults.append("\(`where`) states \(name), which the schema does not declare")
                }
            }
            for (name, sub) in properties {
                guard let held = object[name], let rule = sub as? [String: Any] else { continue }
                check(held, rule, root, "\(`where`).\(name)", &faults)
            }
        }

        if let list = value as? [Any], let items = schema["items"] as? [String: Any] {
            for (index, held) in list.enumerated() {
                check(held, items, root, "\(`where`)[\(index)]", &faults)
            }
        }
    }

    private static func matches(_ value: Any, _ wanted: String) -> Bool {
        switch wanted {
        case "null": value is NSNull
        case "integer": (value as? NSNumber).map { isBool($0) == false } ?? false
        case "boolean": isBool(value)
        case "number": value is NSNumber && isBool(value) == false
        case "string": value is String
        case "array": value is [Any]
        case "object": value is [String: Any]
        default: false
        }
    }

    private static func isBool(_ value: Any) -> Bool {
        if type(of: value) == Bool.self { return true }
        guard let number = value as? NSNumber else { return false }
        #if canImport(Darwin)
        return CFGetTypeID(number) == CFBooleanGetTypeID()
        #else
        return String(cString: number.objCType) == "c"
        #endif
    }

    private static func equal(_ left: Any, _ right: Any) -> Bool {
        if let one = left as? String, let two = right as? String { return one == two }
        if let one = left as? NSNumber, let two = right as? NSNumber { return one == two }
        return false
    }
}

public enum JsonSchemaFault: Error {
    case notAnObject(String)
}
