/// Identifies one control the user can record as in place.
public struct ControlKey: Hashable, Sendable, CustomStringConvertible {
    public let value: String
    public init(_ value: String) { self.value = value }
    public var description: String { value }
}

/// How a control is identified across a model. Spec section 5.3.
///
/// A control has no identifier in the catalogue that survives an edit to its
/// wording, so the identity is a hash of the wording itself, scoped by what
/// the control belongs to. Two components each get their own key for the same
/// control, while every link shares one key and every zone shares one, because
/// the spec consolidates those two.
public enum ControlIdentity {
    /// djb2 over the UTF-8 bytes of the normalised description.
    ///
    /// `hash = 5381`, then `hash = hash * 33 + byte`, kept to unsigned 32 bits
    /// and rendered as 8 lower-case hex digits. Normalising means trimmed, with
    /// runs of whitespace collapsed to one space, so re-wrapping a description
    /// does not lose the user's tick.
    public static func fingerprint(of description: String) -> String {
        var hash: UInt32 = 5381
        for byte in Array(normalised(description).utf8) {
            hash = hash &* 33 &+ UInt32(byte)
        }
        let hex = String(hash, radix: 16)
        return String(repeating: "0", count: max(0, 8 - hex.count)) + hex
    }

    /// A control on one component's threat. A technology's own mitigation is
    /// marked apart, because the same wording can appear as both.
    public static func componentControl(
        componentId: ComponentId,
        threatId: ThreatId,
        description: String,
        isTechnologySpecific: Bool
    ) -> ControlKey {
        let scope = isTechnologySpecific ? ":tech" : ""
        return ControlKey(
            "node:\(componentId.value):\(threatId.value)\(scope)::\(fingerprint(of: description))"
        )
    }

    /// Consolidated across every link. Spec section 5.3.
    public static func connectionControl(threatId: ThreatId, description: String) -> ControlKey {
        ControlKey("connection:\(threatId.value)::\(fingerprint(of: description))")
    }

    /// Consolidated across every zone. Spec section 5.3.
    public static func zoneControl(threatId: ThreatId, description: String) -> ControlKey {
        ControlKey("zone:\(threatId.value)::\(fingerprint(of: description))")
    }

    /// Every key belonging to one component starts with this. `RemoveComponents`
    /// prunes by it.
    public static func componentPrefix(_ componentId: ComponentId) -> String {
        "node:\(componentId.value):"
    }

    private static func normalised(_ description: String) -> String {
        var words: [String] = []
        var current = ""
        for character in description {
            if character.isWhitespace {
                if current.isEmpty == false { words.append(current); current = "" }
            } else {
                current.append(character)
            }
        }
        if current.isEmpty == false { words.append(current) }
        return words.joined(separator: " ")
    }
}
