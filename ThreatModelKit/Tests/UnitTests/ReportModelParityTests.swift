import ArchitectureDSL
import Testing
import ThreatModelKit

/// The parity walk for the analysis, the report and the exports.
///
/// `WindowModelParityTests` pairs every attribute the languages read with the
/// window control that writes it. This suite pairs the same attributes with
/// the three consumers on the other side of the model: the analysis that reads
/// the value, the report section that states it, and the exports that carry
/// it.
@Suite("The analysis, the report and the exports against every language attribute")
struct ReportModelParityTests {
    /// What one consumer does about one attribute.
    enum Reading: Equatable {
        /// The analysis that reads the value, or the report section that
        /// states it.
        case reads(String)
        /// The reason no analysis reads the value, or no section states it.
        case nothingReads(String)
    }

    /// A file `threatmodeller export` writes.
    enum Export: String, CaseIterable, Sendable {
        case otm
        case threatcl
        case json
    }

    /// One attribute, against the three consumers.
    struct Row: Equatable {
        let analysis: Reading
        let report: Reading
        let exports: Set<Export>
    }

    // MARK: the list

    /// Keyed by `<language>.<block name>.<attribute>`, the same word
    /// `LanguageVocabulary.attributeKeys` gives.
    static let list: [String: Row] = architecture
        .merging(controlsAndTrees) { first, _ in first }
        .merging(governanceAndPolicy) { first, _ in first }
        .merging(library) { first, _ in first }

    // MARK: the walk

    /// The keys the list states nothing about.
    static func attributesWithNoRow(_ keys: [String], in list: [String: Row]) -> [String] {
        keys.filter { list[$0] == nil }.sorted()
    }

    /// The rows for words no parser reads.
    static func rowsForNoWord(_ keys: [String], in list: [String: Row]) -> [String] {
        let known = Set(keys)
        return list.keys.filter { known.contains($0) == false }.sorted()
    }

    @Test func everyAttributeIsPaired() {
        let missing = Self.attributesWithNoRow(LanguageVocabulary.attributeKeys, in: Self.list)

        #expect(
            missing.isEmpty,
            """
            The report parity list states no consumer and no reason for: \
            \(missing.joined(separator: ", ")). \
            Add the analysis, the section and the exports, or a row that \
            states why none reads it.
            """
        )
    }

    @Test func theListNamesNoAttributeTheLanguagesDoNotRead() {
        let stale = Self.rowsForNoWord(LanguageVocabulary.attributeKeys, in: Self.list)

        #expect(
            stale.isEmpty,
            """
            The report parity list states a row for words no parser reads: \
            \(stale.joined(separator: ", ")).
            """
        )
    }

    @Test func theWalkNamesAnAttributeWithNoRow() {
        let list = ["arch.component.name": Self.nested("component")]

        #expect(
            Self.attributesWithNoRow(
                ["arch.component.name", "arch.component.colour"],
                in: list
            ) == ["arch.component.colour"]
        )
    }

    @Test func theWalkNamesARowForAWordNoParserReads() {
        let list = [
            "arch.component.name": Self.nested("component"),
            "arch.component.colour": Self.nested("component")
        ]

        #expect(
            Self.rowsForNoWord(["arch.component.name"], in: list)
                == ["arch.component.colour"]
        )
    }

    @Test func everyReasonSaysSomething() {
        for (key, row) in Self.list {
            for reading in [row.analysis, row.report] {
                guard case .nothingReads(let reason) = reading else { continue }
                #expect(reason.isEmpty == false, "\(key) states an empty reason")
            }
        }
    }

    @Test func everyConsumerThatReadsNamesOne() {
        for (key, row) in Self.list {
            for reading in [row.analysis, row.report] {
                guard case .reads(let place) = reading else { continue }
                #expect(place.isEmpty == false, "\(key) names an empty place")
            }
        }
    }
}
