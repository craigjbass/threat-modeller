import Foundation
import Testing
import ThreatModelKit

/// The behaviour every `ThreatModelGateway` must exhibit, expressed entirely in
/// Domain objects. Run it against every implementation.
public func verifyThreatModelGatewayContract(_ make: () -> ThreatModelGateway) {
    let component = Component(
        id: ComponentId("c1"),
        technologyId: TechnologyId("aws-ec2"),
        position: Point(x: 0, y: 0),
        sensitivity: .internalData
    )

    let empty = make()
    #expect(empty.current().components.isEmpty)

    let saved = make()
    saved.save(ThreatModel(name: "Payments", components: [component]))
    #expect(saved.current().name == "Payments")
    #expect(saved.current().components.map(\.id) == [component.id])

    // `mutate` reads, changes and writes without a gap, and hands back
    // whatever the change returns.
    let mutated = make()
    let count = mutated.mutate { model -> Int in
        model.components.append(component)
        return model.components.count
    }
    #expect(count == 1)
    #expect(mutated.current().components.map(\.id) == [component.id])

    // Two hundred appends, each read-modify-write, all from different threads.
    // Every one must survive: that is the whole reason the operation exists.
    let raced = make()
    DispatchQueue.concurrentPerform(iterations: 200) { index in
        raced.mutate { model in
            model.components.append(
                Component(
                    id: ComponentId("c\(index)"),
                    technologyId: TechnologyId("aws-ec2"),
                    position: Point(x: 0, y: 0),
                    sensitivity: .internalData
                )
            )
        }
    }
    #expect(raced.current().components.count == 200)

    // Reading while others write must not trap or tear.
    let read = make()
    DispatchQueue.concurrentPerform(iterations: 100) { index in
        if index.isMultiple(of: 2) {
            read.mutate { $0.name = "n\(index)" }
        } else {
            _ = read.current().name
        }
    }
    #expect(read.current().name.isEmpty == false)

    // MARK: history

    let history = make()
    #expect(history.canUndo == false)
    #expect(history.canRedo == false)
    #expect(history.undo() == false)
    #expect(history.redo() == false)

    history.mutate { $0.name = "one" }
    history.mutate { $0.name = "two" }
    #expect(history.canUndo)

    #expect(history.undo())
    #expect(history.current().name == "one")
    #expect(history.canRedo)

    #expect(history.undo())
    #expect(history.current().name == "Untitled")
    #expect(history.canUndo == false)

    #expect(history.redo())
    #expect(history.current().name == "one")
    #expect(history.redo())
    #expect(history.current().name == "two")
    #expect(history.canRedo == false)

    // A change after an undo drops what was redoable: the user has taken a
    // different branch, and offering to redo the abandoned one would be a lie.
    #expect(history.undo())
    history.mutate { $0.name = "three" }
    #expect(history.canRedo == false)
    #expect(history.current().name == "three")

    // A change that changes nothing is not a step to take back.
    let noChange = make()
    noChange.mutate { $0.name = "one" }
    noChange.mutate { _ in }
    noChange.mutate { model in model.name = model.name }
    #expect(noChange.undo())
    #expect(noChange.current().name == "Untitled")
    #expect(noChange.canUndo == false)

    // Replacing the model outright — opening a different document — is not
    // something to undo back out of.
    let replaced = make()
    replaced.mutate { $0.name = "one" }
    replaced.save(ThreatModel(name: "another document"))
    #expect(replaced.canUndo == false)
    #expect(replaced.canRedo == false)
}
