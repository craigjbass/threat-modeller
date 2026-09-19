import Foundation

/// Holds the model currently being edited.
///
/// One gateway serves one model. `current()` and `save(_:)` are each atomic,
/// but a use case that reads, changes and writes has a gap between them, and
/// SwiftUI can ask a document for its bytes on a background thread while the
/// main actor is part-way through one. `mutate` closes that gap: every write
/// use case reads, changes and writes in one step.
///
/// `mutate` also records history. The snapshot is taken inside it, before the
/// change, and kept only when the model actually changed: one use case is one
/// undo step, no use case can forget to record one, and a refused change is
/// not a step. `save(_:)` clears the history instead — replacing the model
/// outright is opening a different document, not a change to take back.
public protocol ThreatModelGateway: AnyObject, Sendable {
    func current() -> ThreatModel
    func save(_ model: ThreatModel)
    /// Read, change and write without a gap. Returns whatever the change
    /// returns, so a use case can decide its response inside the same step.
    ///
    /// `label` names the change for the Edit menu: a person who presses Undo
    /// should know what will be taken back.
    func mutate<T>(label: String, _ change: (inout ThreatModel) -> T) -> T
    /// Takes the model back one change, and names it. Nil means there was
    /// nothing to take back.
    func undo() -> String?
    /// Puts back a change that was taken back, and names it.
    func redo() -> String?
    var canUndo: Bool { get }
    var canRedo: Bool { get }
    /// What Undo would take back, and what Redo would put back. Nil when
    /// there is nothing.
    var undoLabel: String? { get }
    var redoLabel: String? { get }
    /// How many times the model has changed. A reader that keeps an answer
    /// works out from this number whether the answer is still about the model
    /// in front of it.
    var revision: Int { get }
}

public extension ThreatModelGateway {
    /// A change nobody has named yet. Every write use case names its own; this
    /// keeps a caller that does not care building.
    func mutate<T>(_ change: (inout ThreatModel) -> T) -> T {
        mutate(label: ChangeLabel.unnamed, change)
    }
}

/// What the Edit menu calls each change.
///
/// One label per write use case, so `Undo Move` and `Undo Tick Control` read
/// as what a person just did.
public enum ChangeLabel {
    public static let unnamed = "Change"
    public static let addComponent = "Add Component"
    public static let addUser = "Add User"
    public static let setUserProperties = "Edit User"
    public static let moveComponents = "Move"
    public static let removeComponents = "Delete"
    public static let mergeComponents = "Merge Components"
    public static let connectComponents = "Connect"
    public static let removeConnection = "Delete Flow"
    public static let setConnectionProperties = "Edit Flow"
    public static let reverseConnection = "Reverse Flow"
    public static let labelConnection = "Label Flow"
    public static let addZone = "Draw Zone"
    public static let resizeZone = "Resize Zone"
    public static let moveZones = "Move Zone"
    public static let reorderZones = "Reorder Zones"
    public static let removeZone = "Delete Zone"
    public static let setZoneProperties = "Edit Zone"
    public static let setComponentProperties = "Edit Component"
    public static let changeComponentTechnology = "Change Technology"
    public static let arrangeDiagram = "Lay Out"
    public static let moveTechnologyToLibrary = "Move to Library"
    public static let paste = "Paste"
    public static let duplicate = "Duplicate"
    public static let recordControl = "Tick Control"
    public static let setControlStatus = "Set Control Status"
    public static let setControlEvidence = "Set Evidence"
    public static let setControlNote = "Set Control Note"
    public static let overrideSeverity = "Set Severity"
    public static let clearSeverityOverride = "Clear Severity"
    public static let setCompensatingControl = "Set Compensating Control"
    public static let setLikelihoodFinding = "Set Likelihood"
    public static let configurePathwayMitigations = "Set Pathway Mitigations"
    public static let setMitigatesEdge = "Set Mitigates Edge"
    public static let setAssumption = "Set Assumption"
    public static let removeAssumption = "Remove Assumption"
    public static let setUseCase = "Set Use Case"
    public static let removeUseCase = "Remove Use Case"
    public static let setExclusion = "Set Exclusion"
    public static let removeExclusion = "Remove Exclusion"
    public static let setSystemAsset = "Set Asset"
    public static let removeSystemAsset = "Remove Asset"
    public static let setComponentAsset = "Set Component Asset"
    public static let removeComponentAsset = "Remove Component Asset"
    public static let setConnectionAssets = "Set What A Connection Carries"
    public static let setSystemFacts = "Set System Facts"
    public static let setSystemAttribute = "Set System Attribute"
    public static let removeSystemAttribute = "Remove System Attribute"
    public static let setSystemDiagram = "Set Diagram"
    public static let removeSystemDiagram = "Remove Diagram"
    public static let setThirdParty = "Set Third Party"
    public static let removeThirdParty = "Remove Third Party"
    public static let setComponentProvider = "Set Provided By"
    public static let setFacedThreatActors = "Set Threat Actors Faced"
    public static let setRiskTolerance = "Set Risk Tolerance"
    public static let setRequiresEvidenceAbove = "Set Requires Evidence Above"
    public static let setLocalThreatActor = "Set Threat Actor"
    public static let removeLocalThreatActor = "Remove Threat Actor"
    public static let setClearance = "Set Clearance"
    public static let removeClearance = "Remove Clearance"
    public static let createCustomTechnology = "New Technology"
    public static let editCustomTechnology = "Edit Technology"
    public static let deleteCustomTechnology = "Delete Technology"
    public static let renameThreatModel = "Rename"
    public static let importArchitecture = "Import Architecture"
    public static let applyAnswers = "Apply Answers"
    public static let adoptCatalogue = "Take Catalogue"
    public static let save = "Save"
}

/// The model store for one open document. A document seeds it on open and
/// reads it back on save.
///
/// The lock is the whole point: the document's writer runs wherever SwiftUI
/// puts it, and the editor runs on the main actor. `@unchecked Sendable` is
/// stated rather than inferred, because the lock is what makes it safe and the
/// compiler cannot see that.
public final class InMemoryThreatModelGateway: ThreatModelGateway, @unchecked Sendable {
    /// How far back the user can go.
    public static let historyLimit = 100

    /// One step of the history: the model before a change, and what the
    /// change was called.
    private struct Step {
        let model: ThreatModel
        let label: String
    }

    private let lock = NSLock()
    private var model: ThreatModel
    private var past: [Step] = []
    private var future: [Step] = []
    private var changes = 0

    /// How many times the model has changed. Every write to `model` moves it,
    /// and nothing moves it back: an undo is a change like any other.
    public var revision: Int {
        lock.lock()
        defer { lock.unlock() }
        return changes
    }

    public init(_ model: ThreatModel = ThreatModel()) {
        self.model = model
    }

    public func current() -> ThreatModel {
        lock.lock()
        defer { lock.unlock() }
        return model
    }

    /// Replaces the model and forgets the history. Only `CreateThreatModel` and
    /// `OpenThreatModel` call this.
    public func save(_ model: ThreatModel) {
        lock.lock()
        defer { lock.unlock() }
        self.model = model
        past = []
        future = []
        changes += 1
    }

    public func mutate<T>(label: String, _ change: (inout ThreatModel) -> T) -> T {
        lock.lock()
        defer { lock.unlock() }

        let before = model
        let result = change(&model)

        if model != before {
            changes += 1
            past.append(Step(model: before, label: label))
            if past.count > Self.historyLimit { past.removeFirst() }
            // The user has taken a different branch. Offering to redo the
            // abandoned one would be a lie.
            future = []
        }

        return result
    }

    public func undo() -> String? {
        lock.lock()
        defer { lock.unlock() }
        guard let previous = past.popLast() else { return nil }
        changes += 1
        future.append(Step(model: model, label: previous.label))
        model = previous.model
        return previous.label
    }

    public func redo() -> String? {
        lock.lock()
        defer { lock.unlock() }
        guard let next = future.popLast() else { return nil }
        changes += 1
        past.append(Step(model: model, label: next.label))
        model = next.model
        return next.label
    }

    public var undoLabel: String? {
        lock.lock()
        defer { lock.unlock() }
        return past.last?.label
    }

    public var redoLabel: String? {
        lock.lock()
        defer { lock.unlock() }
        return future.last?.label
    }

    public var canUndo: Bool {
        lock.lock()
        defer { lock.unlock() }
        return past.isEmpty == false
    }

    public var canRedo: Bool {
        lock.lock()
        defer { lock.unlock() }
        return future.isEmpty == false
    }
}
