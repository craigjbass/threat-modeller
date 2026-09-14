/// What a system's file states about the catalogue against what is in use.
///
/// The `.arch` file names the catalogue tag the model was written against. A
/// tag that is not the one in use means the threats, the controls and the
/// scores may have moved under the file, so the window states both tags and
/// offers the two things a person can do about it.
struct CatalogueDrift: Equatable {
    let systemName: String
    let fileName: String
    /// The tag the file states.
    let stated: String
    /// The tag the application reads its catalogue from.
    let inUse: String

    var says: String {
        "\(fileName) was written against catalogue \(stated), "
            + "and the catalogue in use is \(inUse)."
    }
}
