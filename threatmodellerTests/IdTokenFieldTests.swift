import SwiftUI
import Testing
@testable import threatmodeller

/// The one control every list of component or asset ids goes through.
///
/// Issue #179: `Uses`, `Reaches` and `Holds` used to draw a `Menu` of one
/// `Toggle` per choice, which closes on every pick. This field draws the
/// chosen ids as tokens and opens a list that stays open until a person
/// closes it, so many picks take one open.
@MainActor
@Suite("The id token field")
struct IdTokenFieldTests {
    /// What one field writes, so a test reads the ids back with no window.
    final class Held {
        var ids: [String]

        init(_ ids: [String] = []) { self.ids = ids }

        var binding: Binding<[String]> {
            Binding(get: { self.ids }, set: { self.ids = $0 })
        }
    }

    private static let choices = [
        IdTokenField.Choice(id: "browser", name: "Web Browser", icon: "circle.fill"),
        IdTokenField.Choice(id: "mobile", name: "Mobile App", icon: "circle.fill"),
        IdTokenField.Choice(id: "terminal", name: "Terminal", icon: "circle.fill")
    ]

    private func aField(
        held: Held,
        choices: [IdTokenField.Choice] = choices,
        search: IdTokenField.Search = IdTokenField.Search()
    ) -> IdTokenField {
        IdTokenField(
            identifier: "test-id-tokens",
            ids: held.binding,
            choices: choices,
            emptyMessage: "No choice to pick yet.",
            search: search
        )
    }

    // MARK: the rows a person searches

    @Test func offersEveryChoiceNotAlreadyHeld() {
        let field = aField(held: Held(["browser"]))

        #expect(field.rows.map(\.id) == ["mobile", "terminal"])
    }

    @Test func narrowsTheRowsToWhatIsTyped() {
        let field = aField(held: Held(), search: IdTokenField.Search(text: "mob"))

        #expect(field.rows.map(\.id) == ["mobile"])
    }

    @Test func aRowTypedByIdIsOffered() {
        let field = aField(held: Held(), search: IdTokenField.Search(text: "terminal"))

        #expect(field.rows.map(\.id) == ["terminal"])
    }

    // MARK: picking many in one open

    @Test func picksThreeInOneOpenWithoutClosing() {
        let held = Held()
        let field = aField(held: held)

        field.open()
        #expect(field.isOpen)

        field.pick(field.rows.first { $0.id == "browser" }!)
        #expect(field.isOpen)
        field.pick(field.rows.first { $0.id == "mobile" }!)
        #expect(field.isOpen)
        field.pick(field.rows.first { $0.id == "terminal" }!)

        #expect(held.ids == ["browser", "mobile", "terminal"])
        #expect(field.isOpen)
    }

    /// A choice already held is not offered again, so nobody picks one twice.
    @Test func aChoiceAlreadyHeldIsNotPickedTwice() {
        let held = Held(["browser"])
        let field = aField(held: held)

        let again = IdTokenField.Choice(id: "browser", name: "Web Browser", icon: "circle.fill")
        field.pick(again)

        #expect(held.ids == ["browser"])
    }

    // MARK: an id the list no longer holds

    @Test func choiceOfAnIdTheListStillHoldsGivesIt() {
        let field = aField(held: Held(["browser"]))

        #expect(field.choice(of: "browser")?.name == "Web Browser")
    }

    @Test func choiceOfAnIdTheListNoLongerHoldsGivesNil() {
        let field = aField(held: Held(["gone"]))

        #expect(field.choice(of: "gone") == nil)
    }

    @Test func aTokenForAnIdTheListNoLongerHoldsDrawsTheBareId() {
        let field = aField(held: Held(["gone"]))

        #expect(field.nameForToken("gone") == "gone")
    }

    @Test func removingAnotherTokenLeavesTheUnknownIdInIds() {
        let held = Held(["gone", "browser"])
        let field = aField(held: held)

        field.remove("browser")

        #expect(held.ids == ["gone"])
    }

    // MARK: taking a token off

    @Test func aTokenComesOff() {
        let held = Held(["browser", "mobile"])
        let field = aField(held: held)

        field.remove("browser")

        #expect(held.ids == ["mobile"])
    }

    // MARK: closing

    @Test func closingClearsWhatWasTypedAndShutsTheList() {
        let field = aField(held: Held(), search: IdTokenField.Search(isOpen: true, text: "mob"))

        field.close()

        #expect(field.isOpen == false)
        #expect(field.typed == "")
    }

    // MARK: no choice at all

    @Test func withNoChoiceTheFieldStatesTheEmptyMessage() {
        let field = aField(held: Held(), choices: [])

        #expect(field.choices.isEmpty)
        #expect(field.emptyMessage == "No choice to pick yet.")
    }
}
