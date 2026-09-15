/// Joins the answers of a split system, and routes them back to their files.
///
/// A controls file mirrors an architecture file by stem: `arch/edge.arch`
/// pairs with `controls/edge.controls`. The compile reads every file as one
/// set, and writes each answer back to the file that mirrors the architecture
/// file the element it answers came from.
public enum ControlsSourceMerge {
    /// Every answer the files hold, as one controls file's text.
    ///
    /// The files state one system, so the merged text states that system once
    /// and holds every answer. A file that states another system's name is
    /// dropped and the caller reports it.
    public static func text(
        of files: [String: String],
        sources: ControlsSourceGateway
    ) -> String? {
        var systemName: String?
        var catalogueTag: String?
        var riskTolerance: String?
        var answers: [SourceThreatAnswer] = []
        var trees: [SourceTreeAnswer] = []

        for (_, text) in files.sorted(by: { $0.key < $1.key }) {
            guard text.isEmpty == false, let source = sources.read(text).source else { continue }
            systemName = systemName ?? source.systemName
            catalogueTag = catalogueTag ?? source.catalogueTag
            riskTolerance = riskTolerance ?? source.riskTolerance
            answers += source.answers
            trees += source.trees
        }

        guard let systemName else { return nil }
        return sources.write(
            ControlsSource(
                systemName: systemName,
                catalogueTag: catalogueTag,
                riskTolerance: riskTolerance,
                answers: answers,
                trees: trees
            )
        )
    }

    /// The compiled answers, split into one text per controls file.
    ///
    /// `originOf` names the architecture file each element came from, and
    /// `controlsPathOf` turns that into the controls file that mirrors it. An
    /// answer whose element the architecture no longer declares stays in the
    /// file that already holds it.
    public static func split(
        _ compiled: ControlsSource,
        sources: ControlsSourceGateway,
        held: [String: String],
        originOf: (SourceThreatAnswer) -> String?,
        controlsPathOf: (String) -> String
    ) -> [String: String] {
        // Where an answer already sits, so a stale one stays where it is.
        var heldBy: [String: String] = [:]
        for (path, text) in held {
            guard let source = sources.read(text).source else { continue }
            for answer in source.answers { heldBy[answer.key.value] = path }
        }

        var answersByPath: [String: [SourceThreatAnswer]] = [:]
        for answer in compiled.answers {
            let path = originOf(answer).map(controlsPathOf)
                ?? heldBy[answer.key.value]
                ?? held.keys.sorted().first
                ?? controlsPathOf("")
            answersByPath[path, default: []].append(answer)
        }

        // Every tree goes to the file that already holds it, else the first.
        var treesByPath: [String: [SourceTreeAnswer]] = [:]
        if compiled.trees.isEmpty == false {
            let path = held.keys.sorted().first ?? controlsPathOf("")
            treesByPath[path] = compiled.trees
        }

        var written: [String: String] = [:]
        for path in Set(answersByPath.keys).union(treesByPath.keys).union(held.keys) {
            written[path] = sources.write(
                ControlsSource(
                    systemName: compiled.systemName,
                    catalogueTag: compiled.catalogueTag,
                    riskTolerance: compiled.riskTolerance,
                    answers: answersByPath[path] ?? [],
                    trees: treesByPath[path] ?? []
                )
            )
        }
        return written
    }
}
