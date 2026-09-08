/// Reads and writes the controls language.
public protocol ControlsSourceGateway: Sendable {
    func read(_ text: String) -> ControlsRead
    func write(_ source: ControlsSource) -> String
}
