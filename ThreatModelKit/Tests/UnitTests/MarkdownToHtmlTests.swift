import Foundation
import Testing
@testable import ThreatModelKit

@Suite("The report as one page")
struct MarkdownToHtmlTests {
    private func body(_ markdown: String, pictures: MarkdownToHtml.Pictures = [:]) -> String {
        MarkdownToHtml.html(of: markdown, title: "model", pictures: pictures)
    }

    @Test func writesAHeadingAtItsLevel() {
        let html = body("# One\n\n## Two\n\n### Three")

        #expect(html.contains("<h1>One</h1>"))
        #expect(html.contains("<h2>Two</h2>"))
        #expect(html.contains("<h3>Three</h3>"))
    }

    @Test func writesTheTitleInTheHead() {
        let html = MarkdownToHtml.html(of: "# One", title: "A & B")

        #expect(html.contains("<title>A &amp; B</title>"))
    }

    @Test func writesOneListForARunOfBullets() {
        let html = body("- one\n- two\n\nAfter.")

        #expect(html.contains("<ul>\n<li>one</li>\n<li>two</li>\n</ul>"))
        #expect(html.contains("<p>After.</p>"))
    }

    @Test func keepsANestedBulletWithTheItemAboveIt() {
        let html = body("- one\n  - under\n- two")

        #expect(html.contains("<li>one<br><span class=\"under\">under</span></li>"))
        #expect(html.contains("<li>two</li>"))
    }

    @Test func writesATableWithAHeadRow() {
        let html = body("| A | B |\n| --- | --- |\n| 1 | 2 |")

        #expect(html.contains("<tr><th>A</th><th>B</th></tr>"))
        #expect(html.contains("<tr><td>1</td><td>2</td></tr>"))
        // The dashes are the Markdown rule, not a row of the table.
        #expect(html.contains("<td>---</td>") == false)
    }

    @Test func holdsAPictureItWasGiven() {
        let html = body(
            "![what it protects](model-control-1.svg)",
            pictures: ["model-control-1.svg": "<svg><circle/></svg>"]
        )

        #expect(html.contains("<figure><svg><circle/></svg></figure>"))
    }

    @Test func linksAPictureItWasNotGiven() {
        let html = body("![what it protects](model-control-1.svg)")

        #expect(
            html.contains("<img alt=\"what it protects\" src=\"model-control-1.svg\">")
        )
    }

    @Test func dropsTheXmlPrologueFromAPicture() {
        let html = body(
            "![a](a.svg)",
            pictures: ["a.svg": "<?xml version=\"1.0\"?>\n<svg></svg>"]
        )

        #expect(html.contains("<figure><svg></svg></figure>"))
    }

    @Test func writesTheWholePictureUnderTheTitle() {
        let html = MarkdownToHtml.html(
            of: "# One\n\n## Two",
            title: "model",
            wholePicture: "<svg id=\"whole\"></svg>"
        )
        let title = try? #require(html.range(of: "<h1>One</h1>"))
        let whole = try? #require(html.range(of: "<figure class=\"whole\">"))
        let next = try? #require(html.range(of: "<h2>Two</h2>"))

        #expect(title != nil && whole != nil && next != nil)
        if let title, let whole, let next {
            #expect(title.upperBound <= whole.lowerBound)
            #expect(whole.upperBound <= next.lowerBound)
        }
    }

    @Test func writesAnHttpLinkAsALink() {
        let html = body("- Source: [a page](https://example.com/x)")

        #expect(html.contains("<a href=\"https://example.com/x\">a page</a>"))
    }

    @Test func writesAnyOtherLinkAsText() {
        // Nothing in a report opens a scheme the reader did not expect.
        let html = body("- Source: [click](javascript:alert(1))")

        #expect(html.contains("<a href") == false)
        #expect(html.contains("click (javascript:alert(1))"))
    }

    @Test func writesCodeAndBold() {
        let html = body("Run `swift test` and **stop**.")

        #expect(html.contains("<code>swift test</code>"))
        #expect(html.contains("<strong>stop</strong>"))
    }

    @Test func escapesMarkupInTheText() {
        let html = body("A <script>alert(1)</script> line.")

        #expect(html.contains("<script>") == false)
        #expect(html.contains("&lt;script&gt;"))
    }

    @Test func writesTheStylesheetIntoThePage() {
        let html = body("# One")

        // The page prints as the report, from any folder, with no network.
        #expect(html.contains("@page { size: A4;"))
        #expect(html.contains("<link") == false)
    }

    @Test func writesANumberedListAsOneOrderedList() {
        let html = body("1. first\n2. second\n3. third\n")

        #expect(html.contains("<ol>"))
        #expect(html.contains("<li>first</li>"))
        #expect(html.contains("<li>second</li>"))
        // The marker belongs to the list, not to the text. A page that keeps
        // it shows the number twice.
        #expect(html.contains("1. first") == false)
        #expect(html.components(separatedBy: "<ol>").count == 2)
    }

    @Test func keepsAnIndentedLineInsideTheItemAboveIt() {
        let html = body("1. first\n   more about first\n2. second\n")

        // One list, not two: closing it here would number `second` as one.
        #expect(html.components(separatedBy: "<ol>").count == 2)
        #expect(html.contains("more about first"))
        #expect(html.contains("<p>more about first</p>") == false)
    }

    @Test func aBulletListAfterANumberedOneStartsItsOwnList() {
        let html = body("1. first\n- bullet\n")

        #expect(html.contains("<ol>"))
        #expect(html.contains("<ul>"))
    }
}
