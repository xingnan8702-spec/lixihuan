import Foundation

public enum SOCKS5CodecError: Error, Equatable, Sendable {
    case bufferLimitExceeded(Int)
    case invalidVersion(UInt8)
    case invalidReserved(UInt8)
    case invalidUDPReserved(UInt16)
    case unsupportedUDPFragment(UInt8)
    case truncatedUDPDatagram
    case udpDatagramTooLarge(Int)
    case noAuthenticationMethod
    case unsupportedAuthenticationMethod(UInt8)
    case unsupportedCommand(UInt8)
    case unknownCommand(UInt8)
    case unknownAddressType(UInt8)
    case invalidDomainLength(Int)
    case invalidUTF8
    case zeroPort
    case unknownReply(UInt8)
}

public enum SOCKS5ParseResult<Value: Equatable & Sendable>: Equatable, Sendable {
    case incomplete
    case complete(Value, remainder: Data)
}

public struct SOCKS5Greeting: Equatable, Sendable {
    public let methods: [UInt8]

    public init(methods: [UInt8]) {
        self.methods = methods
    }
}

public enum SOCKS5Command: UInt8, Equatable, Sendable {
    case connect = 0x01
    case bind = 0x02
    case udpAssociate = 0x03
}

public struct SOCKS5Request: Equatable, Sendable {
    public let command: SOCKS5Command
    public let destination: Address

    public init(command: SOCKS5Command, destination: Address) {
        self.command = command
        self.destination = destination
    }
}

public enum SOCKS5ReplyCode: UInt8, Equatable, Sendable {
    case succeeded = 0x00
    case generalFailure = 0x01
    case connectionNotAllowed = 0x02
    case networkUnreachable = 0x03
    case hostUnreachable = 0x04
    case connectionRefused = 0x05
    case ttlExpired = 0x06
    case commandNotSupported = 0x07
    case addressTypeNotSupported = 0x08
}

public struct SOCKS5Reply: Equatable, Sendable {
    public let code: SOCKS5ReplyCode
    public let boundAddress: Address

    public init(code: SOCKS5ReplyCode, boundAddress: Address) throws {
        self.code = code
        self.boundAddress = boundAddress
    }
}

/// Foundation-only SOCKS5 control-message codec.
///
/// Every parser accepts an accumulated TCP prefix. It returns `.incomplete` for a
/// split message and preserves bytes after one complete message as `remainder`.
/// The parsed control message is capped independently of any glued application data.
public enum SOCKS5Codec {
    public static let version: UInt8 = 0x05
    public static let noAuthentication: UInt8 = 0x00
    public static let noAcceptableMethods: UInt8 = 0xff
    public static let maximumDomainLength = 253
    public static let maximumControlMessageLength = 260

    public static func parseGreeting(_ data: Data) throws -> SOCKS5ParseResult<SOCKS5Greeting> {
        guard data.count >= 2 else { return try incomplete(data) }
        let bytes = [UInt8](data.prefix(2))
        guard bytes[0] == version else { throw SOCKS5CodecError.invalidVersion(bytes[0]) }
        let count = Int(bytes[1])
        guard count > 0 else { throw SOCKS5CodecError.noAuthenticationMethod }
        let length = 2 + count
        guard length <= maximumControlMessageLength else {
            throw SOCKS5CodecError.bufferLimitExceeded(length)
        }
        guard data.count >= length else { return try incomplete(data) }
        let methods = Array(data[2..<length])
        guard methods.contains(noAuthentication) else {
            throw SOCKS5CodecError.noAuthenticationMethod
        }
        return .complete(SOCKS5Greeting(methods: methods), remainder: Data(data.dropFirst(length)))
    }

    public static func encodeNoAuthenticationSelection() -> Data {
        Data([version, noAuthentication])
    }

    public static func encodeNoAcceptableMethodsSelection() -> Data {
        Data([version, noAcceptableMethods])
    }

    public static func parseMethodSelection(_ data: Data) throws -> SOCKS5ParseResult<UInt8> {
        guard data.count >= 2 else { return try incomplete(data) }
        let bytes = [UInt8](data.prefix(2))
        guard bytes[0] == version else { throw SOCKS5CodecError.invalidVersion(bytes[0]) }
        guard bytes[1] == noAuthentication else {
            throw SOCKS5CodecError.unsupportedAuthenticationMethod(bytes[1])
        }
        return .complete(bytes[1], remainder: Data(data.dropFirst(2)))
    }

    public static func parseRequest(_ data: Data) throws -> SOCKS5ParseResult<SOCKS5Request> {
        guard data.count >= 4 else { return try incomplete(data) }
        let header = [UInt8](data.prefix(4))
        guard header[0] == version else { throw SOCKS5CodecError.invalidVersion(header[0]) }
        guard header[2] == 0 else { throw SOCKS5CodecError.invalidReserved(header[2]) }

        let command: SOCKS5Command
        switch header[1] {
        case SOCKS5Command.connect.rawValue:
            command = .connect
        case SOCKS5Command.udpAssociate.rawValue:
            command = .udpAssociate
        case SOCKS5Command.bind.rawValue:
            throw SOCKS5CodecError.unsupportedCommand(header[1])
        default:
            throw SOCKS5CodecError.unknownCommand(header[1])
        }

        let parsed = try parseAddress(
            in: data,
            offset: 3,
            requireNonZeroPort: command == .connect
        )
        guard let parsed else { return try incomplete(data) }
        if command == .udpAssociate,
           parsed.address.port == 0,
           !isUnspecifiedIPAddress(parsed.address) {
            throw SOCKS5CodecError.zeroPort
        }
        return .complete(
            SOCKS5Request(command: command, destination: parsed.address),
            remainder: Data(data.dropFirst(parsed.endOffset))
        )
    }

    public static func encodeRequest(_ request: SOCKS5Request) throws -> Data {
        guard request.command == .connect || request.command == .udpAssociate else {
            throw SOCKS5CodecError.unsupportedCommand(request.command.rawValue)
        }
        if request.command == .udpAssociate,
           request.destination.port == 0,
           !isUnspecifiedIPAddress(request.destination) {
            throw SOCKS5CodecError.zeroPort
        }
        var result = Data([version, request.command.rawValue, 0x00])
        try append(
            request.destination,
            requireNonZeroPort: request.command == .connect,
            to: &result
        )
        return result
    }

    public static func parseReply(_ data: Data) throws -> SOCKS5ParseResult<SOCKS5Reply> {
        guard data.count >= 4 else { return try incomplete(data) }
        let header = [UInt8](data.prefix(4))
        guard header[0] == version else { throw SOCKS5CodecError.invalidVersion(header[0]) }
        guard header[2] == 0 else { throw SOCKS5CodecError.invalidReserved(header[2]) }
        guard let code = SOCKS5ReplyCode(rawValue: header[1]) else {
            throw SOCKS5CodecError.unknownReply(header[1])
        }
        let parsed = try parseAddress(in: data, offset: 3, requireNonZeroPort: false)
        guard let parsed else { return try incomplete(data) }
        return .complete(
            try SOCKS5Reply(code: code, boundAddress: parsed.address),
            remainder: Data(data.dropFirst(parsed.endOffset))
        )
    }

    public static func encodeReply(_ reply: SOCKS5Reply) throws -> Data {
        var result = Data([version, reply.code.rawValue, 0x00])
        try append(reply.boundAddress, requireNonZeroPort: false, to: &result)
        return result
    }

    /// Encodes the honest fallback BND endpoint used when the server has no
    /// outbound local endpoint to report.
    public static func encodeUnspecifiedReply(_ code: SOCKS5ReplyCode) throws -> Data {
        let address = try Address.ipv4([0, 0, 0, 0], port: 0)
        return try encodeReply(SOCKS5Reply(code: code, boundAddress: address))
    }

    /// Maps request parsing failures to their SOCKS5 server reply. Both known
    /// unsupported commands and unknown commands use REP 0x07.
    public static func replyCode(forRequestError error: SOCKS5CodecError) -> SOCKS5ReplyCode {
        switch error {
        case .unsupportedCommand, .unknownCommand:
            .commandNotSupported
        case .unknownAddressType:
            .addressTypeNotSupported
        default:
            .generalFailure
        }
    }

    private static func incomplete<Value: Equatable & Sendable>(
        _ data: Data
    ) throws -> SOCKS5ParseResult<Value> {
        guard data.count <= maximumControlMessageLength else {
            throw SOCKS5CodecError.bufferLimitExceeded(data.count)
        }
        return .incomplete
    }

    private static func parseAddress(
        in data: Data,
        offset: Int,
        requireNonZeroPort: Bool
    ) throws -> (address: Address, endOffset: Int)? {
        guard data.count > offset else { return nil }
        let type = data[data.index(data.startIndex, offsetBy: offset)]
        var cursor = offset + 1
        let address: Address

        switch type {
        case 0x01:
            let end = cursor + 4 + 2
            guard end <= maximumControlMessageLength else {
                throw SOCKS5CodecError.bufferLimitExceeded(end)
            }
            guard data.count >= end else { return nil }
            let bytes = Array(data[cursor..<(cursor + 4)])
            cursor += 4
            let port = readPort(data, at: cursor)
            guard !requireNonZeroPort || port != 0 else { throw SOCKS5CodecError.zeroPort }
            address = try Address.ipv4(bytes, port: port)
            cursor += 2
        case 0x04:
            let end = cursor + 16 + 2
            guard end <= maximumControlMessageLength else {
                throw SOCKS5CodecError.bufferLimitExceeded(end)
            }
            guard data.count >= end else { return nil }
            let bytes = Array(data[cursor..<(cursor + 16)])
            cursor += 16
            let port = readPort(data, at: cursor)
            guard !requireNonZeroPort || port != 0 else { throw SOCKS5CodecError.zeroPort }
            address = try Address.ipv6(bytes, port: port)
            cursor += 2
        case 0x03:
            guard data.count > cursor else { return nil }
            let length = Int(data[data.index(data.startIndex, offsetBy: cursor)])
            guard (1...maximumDomainLength).contains(length) else {
                throw SOCKS5CodecError.invalidDomainLength(length)
            }
            cursor += 1
            let end = cursor + length + 2
            guard end <= maximumControlMessageLength else {
                throw SOCKS5CodecError.bufferLimitExceeded(end)
            }
            guard data.count >= end else { return nil }
            let bytes = Array(data[cursor..<(cursor + length)])
            guard let domain = String(bytes: bytes, encoding: .utf8) else {
                throw SOCKS5CodecError.invalidUTF8
            }
            cursor += length
            let port = readPort(data, at: cursor)
            guard !requireNonZeroPort || port != 0 else { throw SOCKS5CodecError.zeroPort }
            address = try Address.domain(domain, port: port)
            cursor += 2
        default:
            throw SOCKS5CodecError.unknownAddressType(type)
        }
        return (address, cursor)
    }

    private static func append(
        _ address: Address,
        requireNonZeroPort: Bool,
        to result: inout Data
    ) throws {
        guard !requireNonZeroPort || address.port != 0 else {
            throw SOCKS5CodecError.zeroPort
        }
        switch address.kind {
        case .ipv4:
            guard let bytes = address.ipBytes, bytes.count == 4 else {
                throw SOCKS5CodecError.unknownAddressType(0x01)
            }
            result.append(0x01)
            result.append(contentsOf: bytes)
        case .ipv6:
            guard let bytes = address.ipBytes, bytes.count == 16 else {
                throw SOCKS5CodecError.unknownAddressType(0x04)
            }
            result.append(0x04)
            result.append(contentsOf: bytes)
        case .domain:
            guard let domain = address.domain else {
                throw SOCKS5CodecError.invalidDomainLength(0)
            }
            let bytes = Array(domain.utf8)
            guard (1...maximumDomainLength).contains(bytes.count) else {
                throw SOCKS5CodecError.invalidDomainLength(bytes.count)
            }
            result.append(0x03)
            result.append(UInt8(bytes.count))
            result.append(contentsOf: bytes)
        }
        result.append(UInt8(address.port >> 8))
        result.append(UInt8(address.port & 0xff))
    }

    private static func isUnspecifiedIPAddress(_ address: Address) -> Bool {
        guard address.kind == .ipv4 || address.kind == .ipv6,
              let bytes = address.ipBytes
        else { return false }
        return bytes.allSatisfy { $0 == 0 }
    }

    private static func readPort(_ data: Data, at offset: Int) -> UInt16 {
        let high = UInt16(data[data.index(data.startIndex, offsetBy: offset)])
        let low = UInt16(data[data.index(data.startIndex, offsetBy: offset + 1)])
        return high << 8 | low
    }
}
