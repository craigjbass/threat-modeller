import ArchitectureDSL
import Testing
import ThreatModelKit

@Suite("Reading an architecture file as tokens")
struct LexerTests {
    private func scan(_ text: String) -> (tokens: [Token], faults: [Diagnostic]) {
        Lexer(text).scan()
    }

    @Test func readsABlockHeader() {
        let scanned = scan("system \"Payments\" {")

        #expect(scanned.tokens.map(\.kind) == [.identifier, .string, .leftBrace, .endOfFile])
        #expect(scanned.tokens[1].text == "Payments")
        #expect(scanned.tokens[2].column == 19)
        #expect(scanned.faults.isEmpty)
    }

    @Test func readsAnAttribute() {
        let scanned = scan("kind = \"private\"")

        #expect(scanned.tokens.map(\.kind) == [.identifier, .equals, .string, .endOfFile])
        #expect(scanned.tokens[0].text == "kind")
        #expect(scanned.tokens[2].text == "private")
    }

    @Test func readsANumberAndABoolean() {
        let scanned = scan("reduces_risk_by = 30\nencrypts = true")

        #expect(scanned.tokens[2].kind == .number)
        #expect(scanned.tokens[2].text == "30")
        #expect(scanned.tokens[5].kind == .boolean)
        #expect(scanned.tokens[5].text == "true")
    }

    @Test func readsAList() {
        let scanned = scan("threats = [\"a\", \"b\"]")

        #expect(
            scanned.tokens.map(\.kind)
                == [.identifier, .equals, .leftBracket, .string, .comma, .string,
                    .rightBracket, .endOfFile]
        )
    }

    @Test func readsAnArrow() {
        let scanned = scan("flow api -> ledger")

        #expect(scanned.tokens.map(\.kind) == [.identifier, .identifier, .arrow, .identifier, .endOfFile])
    }

    @Test func dropsAComment() {
        let scanned = scan("# a note about the system\nsystem \"P\" {")

        #expect(scanned.tokens.first?.kind == .identifier)
        #expect(scanned.tokens.first?.line == 2)
    }

    @Test func countsTheLines() {
        let scanned = scan("one\n\nthree")

        #expect(scanned.tokens[1].line == 3)
        #expect(scanned.tokens[1].column == 1)
    }

    @Test func takesTheEscapesOffAText() {
        let scanned = scan("name = \"The \\\"one\\\" that matters\"")

        #expect(scanned.tokens[2].text == "The \"one\" that matters")
    }

    @Test func saysSoWhenATextHasNoClosingQuotationMark() {
        let scanned = scan("name = \"unfinished\n")

        #expect(scanned.faults.count == 1)
        #expect(scanned.faults[0].severity == .error)
        #expect(scanned.faults[0].line == 1)
        #expect(scanned.faults[0].column == 8)
    }

    @Test func saysSoWhenTheFileHoldsACharacterItCannotRead() {
        let scanned = scan("kind = ?")

        #expect(scanned.faults.count == 1)
        #expect(scanned.faults[0].message.contains("?"))
        #expect(scanned.faults[0].column == 8)
    }

    @Test func endsWithAnEndOfFileToken() {
        #expect(scan("").tokens.map(\.kind) == [.endOfFile])
    }
}
