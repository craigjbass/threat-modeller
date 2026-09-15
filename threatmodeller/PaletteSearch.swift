import ThreatModelKit

/// What the palette shows while a person is searching it.
///
/// Declared `nonisolated`: the app target defaults every type to the main
/// actor, and this one is a pure value with no shared state.
nonisolated enum PaletteSearch {
    /// The palette narrowed to what the words match.
    ///
    /// A technology matches by its name or by its description. A category with
    /// no match is dropped, and a provider with no category left is dropped
    /// too, so nothing draws a heading over nothing. Empty words give the
    /// palette back whole.
    static func narrow(_ providers: [ListedProvider], to words: String) -> [ListedProvider] {
        let wanted = words.trimmingWhitespace().lowercased()
        guard wanted.isEmpty == false else { return providers }

        return providers.compactMap { provider in
            let categories = provider.categories.compactMap { category -> ListedCategory? in
                let technologies = category.technologies.filter { matches($0, wanted) }
                guard technologies.isEmpty == false else { return nil }
                return ListedCategory(
                    id: category.id,
                    label: category.label,
                    technologies: technologies
                )
            }
            guard categories.isEmpty == false else { return nil }
            return ListedProvider(
                id: provider.id,
                displayName: provider.displayName,
                categories: categories
            )
        }
    }

    /// Every technology the narrowed palette holds, in the order it draws
    /// them. The arrow keys walk this list.
    static func technologies(of providers: [ListedProvider]) -> [ListedTechnology] {
        providers.flatMap { $0.categories.flatMap(\.technologies) }
    }

    private static func matches(_ technology: ListedTechnology, _ wanted: String) -> Bool {
        technology.name.lowercased().contains(wanted)
            || technology.description.lowercased().contains(wanted)
    }
}

private nonisolated extension String {
    func trimmingWhitespace() -> String {
        var text = self[...]
        while let first = text.first, first.isWhitespace { text = text.dropFirst() }
        while let last = text.last, last.isWhitespace { text = text.dropLast() }
        return String(text)
    }
}
