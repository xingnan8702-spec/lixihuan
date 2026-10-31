import Foundation

public enum ResponseStatus: UInt8, Equatable, Sendable {
    case ok = 0
    case authenticationFailed = 1
    case badRequest = 2
    case dialFailed = 3
    case forbidden = 4
    case internalError = 5
}

public struct Response: Equatable, Sendable {
    public static let maximumMessageLength = 512

    public let status: ResponseStatus
    public let message: String

    public init(status: ResponseStatus, message: String) throws {
        let length = message.utf8.count
        guard length <= Self.maximumMessageLength else {
            throw ProtocolCodecError.messageTooLong(length)
        }
        self.status = status
        self.message = message
    }

    public func encodedBody() throws -> Data {
        let messageBytes = Array(message.utf8)
        guard messageBytes.count <= Self.maximumMessageLength else {
            throw ProtocolCodecError.messageTooLong(messageBytes.count)
        }
        var writer = ByteWriter()
        writer.append(UInt8(1))
        writer.append(status.rawValue)
        writer.append(UInt16(messageBytes.count))
        writer.append(contentsOf: messageBytes)
        return writer.data
    }

    public func encodedFrame() throws -> Data {
        try FrameCodec.encode(body: encodedBody())
    }

    public static func decodeBody(_ body: Data) throws -> Response {
        var reader = ByteReader(body)
        let version = try reader.readUInt8()
        guard version == 1 else { throw ProtocolCodecError.unknownVersion(version) }

        let statusByte = try reader.readUInt8()
        guard let status = ResponseStatus(rawValue: statusByte) else {
            throw ProtocolCodecError.unknownStatus(statusByte)
        }

        let length = Int(try reader.readUInt16())
        guard length <= maximumMessageLength else {
            throw ProtocolCodecError.messageTooLong(length)
        }
        let bytes = try reader.readBytes(count: length)
        guard let message = String(bytes: bytes, encoding: .utf8) else {
            throw ProtocolCodecError.invalidUTF8
        }
        try reader.requireEnd()
        return try Response(status: status, message: message)
    }

    public static func decodeFrame(_ frame: Data) throws -> Response {
        try decodeBody(FrameCodec.decode(frame))
    }
}
