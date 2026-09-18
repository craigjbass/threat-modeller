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

    /// Whether the search list is open, and what is typed into it, held the
    /// way `UserPanel` and `ComponentPanel` hold it in their own `@State`, so
    /// a test reads a mutation back without a window.
    final class Flag {
        var isOpen: Bool
        var search: String

        init(isOpen: Bool = false, search: String = "") {
            self.isOpen = isOpen
            self.search = search
        }

        var isOpenBinding: Binding<Bool> {
            Binding(get: { self.isOpen }, set: { self.isOpen = $0 })
        }

        var searchBinding: Binding<String> {
            Binding(get: { self.search }, set: { self.search = $0 })
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
        flag: Flag = Flag()
    ) -> IdTokenField {
        IdTokenField(
            identifier: "test-id-tokens",
            ids: held.binding,
            choices: choices,
            emptyMessage: "No choice to pick yet.",
            isOpen: flag.isOpenBinding,
            search: flag.searchBinding
        )
    }

    // MARK: the rows a person searches

    @Test func offersEveryChoiceNotAlreadyHeld() {
        let field = aField(held: Held(["browser"]))

        #expect(field.rows.map(\.id) == ["mobile", "terminal"])
    }

    @Test func narrowsTheRowsToWhatIsTyped() {
        let field = aField(held: Held(), flag: Flag(search: "mob"))

        #expect(field.rows.map(\.id) == ["mobile"])
    }

    @Test func aRowTypedByIdIsOffered() {
        let field = aField(held: Held(), flag: Flag(search: "terminal"))

        #expect(field.rows.map(\.id) == ["terminal"])
    }

    // MARK: picking many in one open

    @Test func picksThreeInOneOpenWithoutClosing() {
        let held = Held()
        let flag = Flag()
        let field = aField(held: held, flag: flag)

        field.open()
        #expect(flag.isOpen)

        field.pick(field.rows.first { $0.id == "browser" }!)
        #expect(flag.isOpen)
        field.pick(field.rows.first { $0.id == "mobile" }!)
        #expect(flag.isOpen)
        field.pick(field.rows.first { $0.id == "terminal" }!)

        #expect(held.ids == ["browser", "mobile", "terminal"])
        #expect(flag.isOpen)
    }

    /// A choice already held is not offered again, so nobody picks one twice.
    @Test func aChoiceAlreadyHeldIsNotPickedTwice() {
        let held = Held(["browser"])
        let field = aField(held: held)

        let again = IdTokenField.Choice(id: "browser", name: "Web Browser", icon: "circle.fill")
        field.pick(again)

        #expect(held.ids == ["browser"])
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
        let flag = Flag(isOpen: true, search: "mob")
        let field = aField(held: Held(), flag: flag)

        field.close()

        #expect(flag.isOpen == false)
        #expect(flag.search == "")
    }

    // MARK: no choice at all

    @Test func withNoChoiceTheFieldStatesTheEmptyMessage() {
        let field = aField(held: Held(), choices: [])

        #expect(field.choices.isEmpty)
        #expect(field.emptyMessage == "No choice to pick yet.")
    }
}
