import ArchitectureDSL
import CommandLineApplication
import FileGateways
import Foundation

let application = CommandLineApplication(
    projects: FileSystemProject(),
    architecture: HclArchitectureSource()
)

exit(application.run(arguments: CommandLine.arguments, output: { print($0) }))
