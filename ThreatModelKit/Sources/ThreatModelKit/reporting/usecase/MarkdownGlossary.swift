/// The report's Glossary section.
///
/// Every word here is one the tool uses for itself. A reader who has never
/// used the tool needs them to read the rest of the report.
public enum MarkdownGlossary {
    public static func lines() -> [String] {
        var lines = ["## Glossary", "", "| Word | What it means |", "| --- | --- |"]
        for entry in entries {
            lines.append("| \(entry.word) | \(entry.meaning) |")
        }
        lines.append("")
        return lines
    }

    /// Every word the glossary states. The Report stage draws the same
    /// list as rows, so the two cannot drift.
    public static let entries: [(word: String, meaning: String)] = [
        ("Answered", "a person has said something about the threat: a control is implemented, not applicable or accepted, or a compensating control stands"),
        ("Implemented", "the control is in place, and it lowers the score"),
        ("Not applicable", "the control does not apply here, and it leaves the share the other controls divide"),
        ("Accepted", "the team takes the risk. The threat counts as answered and the score stays where it is"),
        ("Not implemented", "nobody has answered the control. This is what a control starts as"),
        ("Compensating control", "something the team does that answers a threat the catalogue's own controls do not"),
        ("Pathway mitigation", "a reduction a component upstream gives to everything downstream of it"),
        ("Mitigates edge", "one element stated to lower a named threat on another element"),
        ("Adopted", "the mitigation is in place today"),
        ("Assumed", "the team plans the mitigation and has not put it in place. It never lowers the residual score"),
        ("Inherent score", "the score before any control lowered it"),
        ("Residual score", "the score left after every stage has run. This is the number a reader acts on"),
        ("If the assumptions hold", "the residual score with every assumed mitigation counted as in place"),
        ("Risk tolerance", "the risk level the project accepts. A likelihood finding answers a threat only at or below it"),
        ("Prior", "a percentage a person measures directly inside a likelihood finding, instead of picking one of the four tiers"),
        ("Raised by", "what put the threat in the model: a component, a connection or a zone"),
        ("Document control", "the table that states who owns this model, who wrote it, its version and when the team last read it again"),
        ("Executive summary", "the one page that states the verdict, the highest residual risk and what to do first"),
        ("Scope", "what the model covers: the use cases, the users, the adversaries and what the model leaves out"),
        ("Use cases", "what a person does with the system"),
        ("Users", "the legitimate people who use the system, and what each one reaches"),
        ("Adversaries", "the people the model does not trust, who reach the system as a user does"),
        ("Exclusions", "what the model does not cover, and why"),
        ("Data inventory", "the named things of value the system holds, and what protects each one"),
        ("Third parties", "the parties outside the team the system depends on"),
        ("Known vulnerabilities", "the CVEs the system's components state, ranked by priority"),
        ("Policy", "the rules the project enforces for itself, and whether this system keeps them"),
        ("Risk over time", "what the model scored at each sampled commit"),
        ("What changed", "what moved between the previous sampled commit and the working tree"),
        ("Threats raised", "threats the working tree raises that the previous sampled commit did not"),
        ("Threats no longer raised", "threats the previous sampled commit raised that the working tree does not"),
        ("Controls whose status changed", "controls whose answer moved between the previous sampled commit and the working tree"),
        ("Risks newly accepted", "accepted risks added since the previous sampled commit"),
        ("Review dates moved", "accepted risks whose review date changed since the previous sampled commit"),
        ("Score by element", "the score of each element before and after the change, in the What changed section"),
        ("Where the risk sits", "how many open threats sit on a component, a connection or a zone"),
        ("By zone", "the worst score and the component count for each zone"),
        ("Top residual risk", "the highest-scoring threats left after every stage of the score has run"),
        ("Top residual risk in detail", "a picture of where each top residual threat sits, and what stands in the way"),
        ("Methodology", "how the report turns a threat into a score, stage by stage"),
        ("Diagram legend", "what each colour, line and badge on a picture means"),
        ("Findings", "every threat above the project's risk tolerance, which the team must act on"),
        ("What removes the most risk", "the actions ranked by how much residual risk each removes on its own"),
        ("Attack paths", "the routes a walk of the diagram found, from an entry point to a target"),
        ("Attack trees", "the routes a person wrote by hand, and whether each one is still open"),
        ("Protection dependencies", "what a reduction rests on, and what happens if that control fails"),
        ("Recommendations", "what a person says the team should do about a threat"),
        ("Accepted risks", "the risks the organisation decided to carry, and who decided it"),
        ("Assumptions", "what the model takes on trust"),
        ("Assumed mitigations", "a mitigates edge the team plans and has not put in place yet"),
        ("Threat actors", "the people and groups this assessment is written against"),
        ("Glossary", "the list of words this report explains"),
        ("Appendix A", "the full threat register, one stanza per threat"),
        ("Appendix B", "what the model holds: its components, its connections and its zones"),
        ("Appendix C", "the attack paths the narrative did not carry"),
        ("Diagrams", "the pictures a team keeps beside the diagram, such as a sequence or a deployment"),
        ("Components", "the technology elements the diagram draws"),
        ("Connections", "the flows between components"),
        ("Zones", "the network trust boundaries the diagram draws"),
        ("Highest residual risk", "the threats that score worst after every stage has run, named first in the Executive summary"),
        ("Do first", "the actions the Executive summary names as the ones to do before any other"),
        ("overdue", "an accepted risk whose review date has passed")
    ]
}
