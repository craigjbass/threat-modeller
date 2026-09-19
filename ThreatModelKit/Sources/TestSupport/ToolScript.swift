import Foundation
#if canImport(Glibc)
import Glibc
#elseif canImport(Darwin)
import Darwin
#endif

/// An executable shell script a test writes for a gateway to run.
public enum ToolScript {
    /// Writes `text` to `path` as an executable, through a descriptor no
    /// child spawned meanwhile can inherit.
    public static func write(_ text: String, to path: String) throws {
        let descriptor = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0o755)
        guard descriptor >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        defer { close(descriptor) }
        var bytes = Array(text.utf8)
        var written = 0
        while written < bytes.count {
            let count = bytes.withUnsafeMutableBufferPointer { buffer in
                writeBytes(descriptor, buffer.baseAddress! + written, buffer.count - written)
            }
            guard count > 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
            written += count
        }
    }
}

private func writeBytes(_ descriptor: Int32, _ pointer: UnsafeMutablePointer<UInt8>, _ count: Int) -> Int {
    #if canImport(Glibc)
    return Glibc.write(descriptor, pointer, count)
    #else
    return Darwin.write(descriptor, pointer, count)
    #endif
}
