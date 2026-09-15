import Foundation

public protocol SynchroniseAttackUseCase {
    func execute(_ request: SynchroniseAttackRequest) -> SynchroniseAttackResponse
}

public struct SynchroniseAttackRequest: Equatable, Sendable {
    public let root: String
    /// The tag to take, or nil to take the one the project's lock file states,
    /// and `AttackRelease.default` when it states none.
    public let tag: String?

    public init(root: String, tag: String? = nil) {
        self.root = root
        self.tag = tag
    }
}

public enum SynchroniseAttackResponse: Equatable, Sendable {
    /// What arrived: the tag, how many groups and how many techniques.
    case synchronised(tag: String, groups: Int, techniques: Int)
    case notAProject(reason: String)
    case cannotDownload(reason: String)
    case cannotExtract(reason: String)
    case cannotWrite(reason: String)
}

/// Brings the ATT&CK matrix onto this machine.
///
/// The steps are the ones section 4 of the design states: read the tag,
/// download the Enterprise bundle, extract it in Swift, write the two files
/// into the data directory, and write the lock file into the project.
///
/// WARNING: this is the one use case that reaches the network. Opening a
/// project, drawing, compiling and reporting call nothing here.
///
/// A step that fails leaves the previous data where it is and says what
/// failed.
public struct SynchroniseAttack: SynchroniseAttackUseCase {
    private let projects: ProjectSourceGateway
    private let data: AttackDataGateway
    private let downloader: AttackDownloading

    public init(
        projects: ProjectSourceGateway,
        data: AttackDataGateway,
        downloader: AttackDownloading
    ) {
        self.projects = projects
        self.data = data
        self.downloader = downloader
    }

    public func execute(_ request: SynchroniseAttackRequest) -> SynchroniseAttackResponse {
        let layout: ProjectLayout
        do {
            layout = try projects.discover(root: request.root)
        } catch {
            return .notAProject(reason: String(describing: error))
        }

        let lockPath = ProjectConvention.path(layout.directory, AttackLock.fileName)
        let held = (try? projects.read(path: lockPath)).flatMap(AttackLock.read)
        let tag = request.tag ?? held?.tag ?? AttackRelease.default

        let bundle: Data
        do {
            bundle = try downloader.download(from: AttackRelease.address(of: tag))
        } catch let fault as AttackDownloadFault {
            return .cannotDownload(reason: fault.message)
        } catch {
            return .cannotDownload(reason: String(describing: error))
        }

        let extracted: AttackBundle.Extracted
        do {
            extracted = try AttackBundle.extract(bundle)
        } catch let fault as AttackBundle.Fault {
            return .cannotExtract(reason: fault.message)
        } catch {
            return .cannotExtract(reason: String(describing: error))
        }

        let groups = AttackFiles.groupsText(tag: tag, groups: extracted.groups)
        let techniques = AttackFiles.techniquesText(tag: tag, techniques: extracted.techniques)

        do {
            try data.write(groups, fileName: AttackDataLocation.groupsFileName)
            try data.write(techniques, fileName: AttackDataLocation.techniquesFileName)
        } catch {
            return .cannotWrite(reason: String(describing: error))
        }

        let lock = AttackLock(
            repository: AttackRelease.repository,
            tag: tag,
            bundle: AttackRelease.bundlePath(of: tag),
            files: [
                AttackDataLocation.groupsFileName: AttackLock.checksum(groups),
                AttackDataLocation.techniquesFileName: AttackLock.checksum(techniques)
            ]
        )
        do {
            try projects.write(lock.text, to: lockPath)
        } catch {
            return .cannotWrite(reason: String(describing: error))
        }

        return .synchronised(
            tag: tag,
            groups: extracted.groups.count,
            techniques: extracted.techniques.count
        )
    }
}

/// The two files the data directory holds, as text.
public enum AttackFiles {
    private struct GroupsDocument: Codable {
        struct Group: Codable {
            let id: String
            let attackId: String
            let name: String
            let aliases: [String]
            let description: String
            let techniques: [String]
            let techniquesViaSoftware: [String]
        }

        let release: String
        let groups: [Group]
    }

    private struct TechniquesDocument: Codable {
        struct Technique: Codable {
            let id: String
            let name: String
            let tactics: [String]
            let subtechnique: Bool
        }

        let release: String
        let techniques: [Technique]
    }

    public static func groupsText(tag: String, groups: [AttackGroup]) -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let document = GroupsDocument(
            release: tag,
            groups: groups.map {
                GroupsDocument.Group(
                    id: $0.id,
                    attackId: $0.attackId,
                    name: $0.name,
                    aliases: $0.aliases,
                    description: $0.description,
                    techniques: $0.techniques,
                    techniquesViaSoftware: $0.techniquesViaSoftware
                )
            }
        )
        guard let data = try? encoder.encode(document),
              let text = String(data: data, encoding: .utf8) else { return "{}\n" }
        return text + "\n"
    }

    public static func techniquesText(tag: String, techniques: [AttackTechnique]) -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let document = TechniquesDocument(
            release: tag,
            techniques: techniques.map {
                TechniquesDocument.Technique(
                    id: $0.id,
                    name: $0.name,
                    tactics: $0.tactics,
                    subtechnique: $0.isSubTechnique
                )
            }
        )
        guard let data = try? encoder.encode(document),
              let text = String(data: data, encoding: .utf8) else { return "{}\n" }
        return text + "\n"
    }

    /// The groups a `groups.json` holds.
    public static func groups(from text: String) -> [AttackGroup] {
        guard let data = text.data(using: .utf8),
              let document = try? JSONDecoder().decode(GroupsDocument.self, from: data) else {
            return []
        }
        return document.groups.map {
            AttackGroup(
                id: $0.id,
                attackId: $0.attackId,
                name: $0.name,
                aliases: $0.aliases,
                description: $0.description,
                techniques: $0.techniques,
                techniquesViaSoftware: $0.techniquesViaSoftware
            )
        }
    }

    /// The techniques a `techniques.json` holds.
    public static func techniques(from text: String) -> [AttackTechnique] {
        guard let data = text.data(using: .utf8),
              let document = try? JSONDecoder().decode(TechniquesDocument.self, from: data) else {
            return []
        }
        return document.techniques.map {
            AttackTechnique(
                id: $0.id,
                name: $0.name,
                tactics: $0.tactics,
                isSubTechnique: $0.subtechnique
            )
        }
    }
}
