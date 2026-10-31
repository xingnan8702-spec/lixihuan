import Foundation

public enum FrameCodec {
    public static let maximumBodyLength = 65_600

    public static func encode(body: Data) throws -> Data {
        guard !body.isEmpty else { throw ProtocolCodecError.invalidFrameLength(0) }
        guard body.count <= maximumBodyLength else {
            throw ProtocolCodecError.frameTooLarge(body.count)
        }

        var writer = ByteWriter()
        writer.append(UInt32(body.count))
        writer.append(contentsOf: Array(body))
        return writer.data
    }

    /// Decodes exactly one complete frame. The method never allocates according to
    /// an unvalidated length field and rejects both truncation and trailing bytes.
    public static func decode(_ frame: Data) throws -> Data {
        guard frame.count >= 4 else { throw ProtocolCodecError.truncated }
        let prefix = Array(frame.prefix(4))
        let length = Int(UInt32(prefix[0]) << 24
            | UInt32(prefix[1]) << 16
            | UInt32(prefix[2]) << 8
            | UInt32(prefix[3]))

        guard length > 0 else { throw ProtocolCodecError.invalidFrameLength(length) }
        guard length <= maximumBodyLength else {
            throw ProtocolCodecError.frameTooLarge(length)
        }

        let expectedCount = 4 + length
        guard frame.count >= expectedCount else { throw ProtocolCodecError.truncated }
        guard frame.count == expectedCount else {
            throw ProtocolCodecError.trailingBytes(frame.count - expectedCount)
        }
        return frame.subdata(in: 4..<expectedCount)
    }
}
