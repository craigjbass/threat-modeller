/// One edit in flight, and what it writes when it ends.
///
/// A control bound straight to a use case writes once per keystroke and once
/// per slider step. That costs one rescore each time and fills the undo
/// history with letters, so one undo takes back one letter rather than the
/// edit. This value holds what the person has typed or dragged so far and
/// answers one question: what does the end of the edit write?
///
/// Declared `nonisolated`: the app target defaults every type to the main
/// actor, and this one is a pure value with no shared state.
nonisolated struct DeferredEdit<Value: Equatable> {
    /// What the person has typed or dragged, or nil while no edit is in
    /// flight.
    private(set) var draft: Value?

    init() {}

    /// True while a person is typing or dragging.
    var isEditing: Bool { draft != nil }

    /// Records what the control now shows. It writes nothing.
    mutating func edit(_ value: Value) {
        draft = value
    }

    /// What the control shows: the draft while an edit is in flight, and the
    /// model's own value at every other time.
    func shown(_ modelValue: Value) -> Value {
        draft ?? modelValue
    }

    /// Ends the edit and gives the one value to write, or nil when the edit
    /// changed nothing. Either way no edit is in flight afterwards.
    mutating func end(from modelValue: Value) -> Value? {
        let typed = draft
        draft = nil
        guard let typed, typed != modelValue else { return nil }
        return typed
    }

    /// Drops the edit and writes nothing.
    mutating func cancel() {
        draft = nil
    }
}
