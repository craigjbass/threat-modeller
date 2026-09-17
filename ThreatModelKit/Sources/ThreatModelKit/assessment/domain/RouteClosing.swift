/// The order rule: a control that closes a step on an open tree comes first.
///
/// The design
/// `docs/superpowers/specs/2026-09-17-trees-in-the-threat-list-design.md`
/// states the rule once, and this is where it lives. The Controls stage
/// orders the controls of one card by it, and the report's Recommendations
/// orders its list by it before the score and the text decide.
///
/// A control closes a step on an open tree when a tree is open and not stale,
/// and either the control's threat is an open step of that tree, or that tree
/// names the control's description as sufficient to close the whole route.
public enum RouteClosing {
    /// The trees an attacker can still walk end to end.
    public static func openTrees(_ trees: [BoundAttackTree]) -> [BoundAttackTree] {
        trees.filter { $0.isStale == false && $0.isOpen }
    }

    /// Every threat that is an open step of an open tree, with the trees each
    /// threat is a step of, in the order the trees are given.
    public static func openSteps(on trees: [BoundAttackTree]) -> [ThreatKey: [BoundAttackTree]] {
        var found: [ThreatKey: [BoundAttackTree]] = [:]
        for tree in openTrees(trees) {
            for step in tree.steps where step.state == .open {
                guard found[step.key]?.contains(where: { $0.id == tree.id }) != true else { continue }
                found[step.key, default: []].append(tree)
            }
        }
        return found
    }

    /// Every control description an open tree names as sufficient, keyed by
    /// the fingerprint the `.controls` file identifies a control by.
    public static func sufficientControls(
        on trees: [BoundAttackTree]
    ) -> [String: [BoundAttackTree]] {
        var found: [String: [BoundAttackTree]] = [:]
        for tree in openTrees(trees) {
            for control in tree.sufficientControls {
                let fingerprint = ControlIdentity.fingerprint(of: control.description)
                guard found[fingerprint]?.contains(where: { $0.id == tree.id }) != true else { continue }
                found[fingerprint, default: []].append(tree)
            }
        }
        return found
    }

    /// The list with every item that closes a route first. Two items on the
    /// same side of the rule keep the order they had.
    public static func first<Item>(
        _ items: [Item],
        closesARoute: (Item) -> Bool
    ) -> [Item] {
        items.filter { closesARoute($0) } + items.filter { closesARoute($0) == false }
    }
}
