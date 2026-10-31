import Foundation

public struct AuthenticationToken: Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public static let byteCount = 32
    private let bytes: [UInt8]

    public init(_ data: Data) throws {
        guard data.count == Self.byteCount else {
            throw ProtocolCodecError.invalidTokenLength(data.count)
        }
        bytes = Array(data)
    }

    init(validatedBytes bytes: [UInt8]) {
        self.bytes = bytes
    }

    var encodedBytes: [UInt8] { bytes }

    /// A copy intended only for credential-storage adapters. Callers must not log it.
    public func dataRepresentation() -> Data { Data(bytes) }

    public var description: String { "<redacted 256-bit token>" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(reflecting: description) }
}

public enum RequestCommand: UInt8, Equatable, Sendable {
    case tcpConnect = 1
    case udpAssociate = 2
}

public struct Request: Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public let command: RequestCommand
    public let token: AuthenticationToken
    public let target: Address?

    public init(command: RequestCommand, token: AuthenticationToken, target: Address?) throws {
        switch command {
        case .tcpConnect:
            guard let target else { throw ProtocolCodecError.targetRequired }
            guard target.port != 0 else { throw ProtocolCodecError.zeroPort }
        case .udpAssociate:
            guard target == nil else { throw ProtocolCodecError.unexpectedTarget }
        }
        self.command = command
        self.token = token
        self.target = target
    }

    public static func tcpConnect(token: AuthenticationToken, target: Address) throws -> Request {
        try Request(command: .tcpConnect, token: token, target: target)
    }

    public static func udpAssociate(token: AuthenticationToken) throws -> Request {
        try Request(command: .udpAssociate, token: token, target: nil)
    }

    public func encodedBody() throws -> Data {
        var writer = ByteWriter()
        writer.append(UInt8(1))
        writer.append(command.rawValue)
        writer.append(UInt8(AuthenticationToken.byteCount))
        writer.append(contentsOf: token.encodedBytes)
        if let target { target.encode(into: &writer) }
        return writer.data
    }

    public func encodedFrame() throws -> Data {
        try FrameCodec.encode(body: encodedBody())
    }

    public static func decodeBody(_ body: Data) throws -> Request {
        var reader = ByteReader(body)
        let version = try reader.readUInt8()
        guard version == 1 else { throw ProtocolCodecError.unknownVersion(version) }

        let commandByte = try reader.readUInt8()
        guard let command = RequestCommand(rawValue: commandByte) else {
            throw ProtocolCodecError.unknownCommand(commandByte)
        }

        let tokenLength = Int(try reader.readUInt8())
        guard tokenLength == AuthenticationToken.byteCount else {
            throw ProtocolCodecError.invalidTokenLength(tokenLength)
        }
        let token = AuthenticationToken(validatedBytes: try reader.readBytes(count: tokenLength))

        let target: Address?
        switch command {
        case .tcpConnect:
            target = try Address.decode(from: &reader, requireNonZeroPort: true)
        case .udpAssociate:
            target = nil
        }
        try reader.requireEnd()
        return try Request(command: command, token: token, target: target)
    }

    public static func decodeFrame(_ frame: Data) throws -> Request {
        try decodeBody(FrameCodec.decode(frame))
    }

    public var description: String {
        "Request(command: \(command), token: <redacted>, target: \(target?.description ?? "none"))"
    }

    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(reflecting: description) }
}
