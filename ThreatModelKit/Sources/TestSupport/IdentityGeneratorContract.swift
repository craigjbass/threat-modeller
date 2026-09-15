import Testing
import ThreatModelKit

/// The behaviour every `IdentityGenerator` must exhibit.
///
/// An identifier names a component, a zone or a technology for the whole life
/// of a model: it is written into the `.arch` file, it keys an answer in the
/// `.controls` file, and a paste mints a new one. So it must be unique across
/// a run, and it must be a word the languages can hold: a `.arch` file writes
/// it inside quotes and a control key joins it with `:` and `::`.
public func verifyIdentityGeneratorContract(_ subject: IdentityGenerator) {
    // Unique across a run. Two thousand is more than any one model mints, and
    // enough to catch a generator that repeats.
    var seen: Set<String> = []
    for _ in 0 ..< 2_000 {
        let id = subject.next()

        #expect(id.isEmpty == false, "an identifier is never empty")
        #expect(seen.insert(id).inserted, "the identifier \"\(id)\" was minted twice")

        // The shape the model expects. A control key reads `node:<id>:<threat>`
        // and a severity override key reads `node:<id>::<threat>`, so an
        // identifier that held a colon would make one key read as another.
        #expect(id.contains(":") == false, "an identifier holds no colon")
        #expect(id.contains("\"") == false, "an identifier holds no quotation mark")
        #expect(id.contains(" ") == false, "an identifier holds no space")
        #expect(id.contains("\n") == false, "an identifier holds no new line")
        #expect(
            id.allSatisfy { $0.isLetter || $0.isNumber || $0 == "-" || $0 == "_" },
            "the identifier \"\(id)\" holds a character the languages do not write bare"
        )
    }
}
