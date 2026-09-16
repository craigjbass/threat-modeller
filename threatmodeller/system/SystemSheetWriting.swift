/// What every System sheet asks before it turns its write button on.
enum SystemSheetWriting {
    /// True when both fields say something. A block with an empty name or an
    /// empty body is a block a reader cannot use.
    static func states(_ first: String, _ second: String) -> Bool {
        states(first) && states(second)
    }

    static func states(_ text: String) -> Bool {
        text.trimmingCharacters(in: .whitespaces).isEmpty == false
    }

    /// One list, as one line a person edits.
    static func joined(_ items: [String]) -> String {
        items.joined(separator: ", ")
    }

    /// The items of one such line, without the whitespace around each and
    /// without the items that hold nothing.
    static func split(_ text: String) -> [String] {
        text.split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { $0.isEmpty == false }
    }
}
