import ArchitectureDSL
import Foundation
import Testing
@testable import threatmodeller

/// The window has one-to-one parity with the code model.
///
/// Issue #152 and
/// `docs/superpowers/specs/2026-09-17-window-model-parity-design.md`: every
/// attribute the languages read is written from the window. This suite is the
/// parity list. It walks `LanguageVocabulary`, which every parser builds its
/// unknown-attribute message from, and states for each attribute either the
/// accessibility identifier of the control that writes it or the reason the
/// window does not.
///
/// A new attribute in any language fails `everyAttributeIsPaired` until this
/// list gains a row.
@Suite("The window writes every attribute the languages read")
struct WindowModelParityTests {
    /// What the window does about one attribute.
    enum Parity: Equatable {
        /// A control a person can change writes the attribute. The word is the
        /// control's accessibility identifier. An identifier the view builds
        /// from an element id is stated as its fixed prefix.
        case writes(String)
        /// The window writes no value here, and the reason is not a fault: the
        /// word names a nested block, or a gesture writes it, or the window
        /// shows it and nothing changes it.
        case stated(String)
        /// No control writes it. The number is the issue that states what to
        /// build.
        case gap(Int)
    }

    // MARK: the list

    /// Keyed by `<language>.<block name>.<attribute>`, the same word
    /// `LanguageVocabulary.attributeKeys` gives.
    static let list: [String: Parity] = architecture
        .merging(controlsAndTrees) { first, _ in first }
        .merging(governanceAndPolicy) { first, _ in first }
        .merging(library) { first, _ in first }

    // MARK: the walk

    @Test func everyAttributeIsPaired() {
        var missing: [String] = []
        for key in LanguageVocabulary.attributeKeys where Self.list[key] == nil {
            missing.append(key)
        }

        #expect(
            missing.isEmpty,
            """
            The parity list states no control and no reason for: \
            \(missing.sorted().joined(separator: ", ")). \
            Add the control that writes it, or a row that states why not.
            """
        )
    }

    @Test func theListNamesNoAttributeTheLanguagesDoNotRead() {
        let known = Set(LanguageVocabulary.attributeKeys)
        let stale = Self.list.keys.filter { known.contains($0) == false }

        #expect(
            stale.isEmpty,
            """
            The parity list states a row for words no parser reads: \
            \(stale.sorted().joined(separator: ", ")).
            """
        )
    }

    @Test func everyGapNamesAnIssue() {
        for (key, parity) in Self.list {
            guard case .gap(let number) = parity else { continue }
            #expect(number > 0, "\(key) names no issue")
        }
    }

    @Test func everyReasonSaysSomething() {
        for (key, parity) in Self.list {
            guard case .stated(let reason) = parity else { continue }
            #expect(reason.isEmpty == false, "\(key) states an empty reason")
        }
    }

    /// Every identifier the list names is one a window view declares. A
    /// control renamed or deleted without the list following it fails here.
    @Test func everyIdentifierIsOneAViewDeclares() throws {
        let declared = try Self.identifiersTheWindowDeclares()
        var unknown: [String] = []

        for (key, parity) in Self.list {
            guard case .writes(let identifier) = parity else { continue }
            guard declared.contains(identifier) == false else { continue }
            unknown.append("\(key) names \(identifier)")
        }

        #expect(
            unknown.isEmpty,
            """
            The parity list names identifiers no view declares: \
            \(unknown.sorted().joined(separator: ", ")).
            """
        )
    }

    // MARK: what the window declares

    /// Every accessibility identifier the window's own sources state, as a
    /// whole word and as the fixed prefix of an identifier a view builds from
    /// an element id.
    static func identifiersTheWindowDeclares() throws -> Set<String> {
        let window = try windowSourceDirectory()
        var found: Set<String> = []

        let files = FileManager.default.enumerator(atPath: window.path)
        while let step = files?.nextObject() as? String {
            guard step.hasSuffix(".swift") else { continue }
            let text = try String(
                contentsOf: window.appendingPathComponent(step),
                encoding: .utf8
            )
            found.formUnion(identifiers(in: text))
        }
        return found
    }

    /// The identifier of every control one file declares. A view states an
    /// identifier in one of three ways: `.accessibilityIdentifier("x")`,
    /// `identifier: "x"` on a field that applies it for the view, or `id: "x"`
    /// on a menu row, which `ElementMenuView` applies to the button it draws.
    static func identifiers(in text: String) -> Set<String> {
        var found: Set<String> = []
        for opener in ["accessibilityIdentifier(\"", "identifier: \"", "id: \""] {
            var rest = Substring(text)
            while let start = rest.range(of: opener) {
                rest = rest[start.upperBound...]
                // An identifier a view builds from an element id ends at the
                // interpolation, and the list states that fixed prefix.
                guard let end = rest.firstIndex(where: { $0 == "\"" || $0 == "\\" }) else { break }
                let word = String(rest[rest.startIndex..<end])
                if word.isEmpty == false { found.insert(word) }
                rest = rest[end...]
            }
        }
        return found
    }

    /// The `threatmodeller` source directory, found from this file.
    static func windowSourceDirectory(_ thisFile: String = #filePath) throws -> URL {
        let tests = URL(fileURLWithPath: thisFile).deletingLastPathComponent()
        let window = tests.deletingLastPathComponent().appendingPathComponent("threatmodeller")
        guard FileManager.default.fileExists(atPath: window.path) else {
            throw ParityFault.noWindowSource(window.path)
        }
        return window
    }

    enum ParityFault: Error {
        case noWindowSource(String)
    }
}
