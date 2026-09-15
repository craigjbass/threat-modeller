/// The table a report opens with.
///
/// A reader picking up a threat model asks who owns it, who wrote it, which
/// version it is and when it was last read again. A system that states none of
/// that writes no table.
public enum MarkdownDocumentControl {
    public static func lines(_ control: DocumentControl) -> [String] {
        guard control.statesSomething else { return [] }

        var lines = ["## Document control", ""]
        if let description = control.description {
            lines.append(description)
            lines.append("")
        }

        lines.append("| Field | Value |")
        lines.append("| --- | --- |")
        lines.append("| System | \(control.systemName) |")
        if let owner = control.owner { lines.append("| Owner | \(owner) |") }
        if control.authors.isEmpty == false {
            lines.append("| Authors | \(control.authors.joined(separator: ", ")) |")
        }
        if let version = control.version { lines.append("| Version | \(version) |") }
        if let created = control.created { lines.append("| Created | \(created) |") }
        if let reviewed = control.reviewed { lines.append("| Reviewed | \(reviewed) |") }
        if let catalogueTag = control.catalogueTag {
            lines.append("| Catalogue | \(catalogueTag) |")
        }
        for link in control.links { lines.append("| Link | \(link) |") }
        for repository in control.repositories {
            lines.append("| Repository | \(repository) |")
        }
        for attribute in control.attributes {
            lines.append("| \(attribute.name) | \(attribute.value) |")
        }
        lines.append("")
        return lines
    }
}
