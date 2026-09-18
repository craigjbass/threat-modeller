import Foundation

/// The `PATH` a child process searches.
///
/// A window started from the Finder, the Dock or Spotlight inherits launchd's
/// `PATH`, which holds `/usr/bin`, `/bin`, `/usr/sbin` and `/sbin` and nothing
/// the person installed. The shell the person types into holds `~/go/bin`,
/// `/opt/homebrew/bin` and `~/.local/bin` as well, because `~/.zshrc` and its
/// kin add them. So the value is this process's own entries, then every entry
/// the person's interactive login shell prints that the process lacks.
///
/// The shell is asked once per process and the answer kept. A shell that
/// prints no marker, is not there, or does not answer within the limit leaves
/// the process's own `PATH` as it is.
public enum ShellPath {
    /// Wraps the `PATH` the shell prints, so what an rc file prints around it
    /// is ignored.
    public static let marker = "__THREATMODELLER_PATH__"

    /// The `PATH` for a child process, read once.
    public static let value: String = read()

    /// This process's environment with `PATH` set to `value`.
    public static var environment: [String: String] {
        environment(path: value, of: ProcessInfo.processInfo.environment)
    }

    public static func environment(path: String, of environment: [String: String]) -> [String: String] {
        var environment = environment
        environment["PATH"] = path
        return environment
    }

    public static func read(
        shell: String = ProcessInfo.processInfo.environment["SHELL"] ?? "/bin/sh",
        processPath: String = ProcessInfo.processInfo.environment["PATH"] ?? "",
        timeout: TimeInterval = 5
    ) -> String {
        guard let printed = ask(shell, timeout: timeout),
              let shellPath = between(marker, in: printed)
        else { return processPath }

        var entries = processPath.split(separator: ":").map(String.init)
        for entry in shellPath.split(separator: ":").map(String.init) where !entries.contains(entry) {
            entries.append(entry)
        }
        return entries.joined(separator: ":")
    }

    /// What the shell printed, or nil when it is not there or was killed.
    private static func ask(_ shell: String, timeout: TimeInterval) -> String? {
        // `-i` runs `~/.zshrc`, the file most people set PATH in; `-l` runs
        // `~/.zprofile`; `-c` runs the one command and exits.
        // `${PATH}` with braces: `$PATH` followed by the marker would read as
        // one longer variable name.
        let answer = try? ChildProcess.run(
            shell,
            ["-ilc", "echo \"\(marker)${PATH}\(marker)\""],
            environment: ProcessInfo.processInfo.environment,
            timeout: timeout,
            readsNoInput: true
        )
        guard let answer, answer.timerKilledIt == false else { return nil }
        return answer.output
    }

    private static func between(_ marker: String, in text: String) -> String? {
        guard let start = text.range(of: marker),
              let end = text.range(of: marker, range: start.upperBound..<text.endIndex)
        else { return nil }
        return String(text[start.upperBound..<end.lowerBound])
    }
}
