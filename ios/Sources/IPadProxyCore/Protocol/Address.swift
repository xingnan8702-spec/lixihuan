import Foundation

public struct Address: Equatable, Sendable, CustomStringConvertible {
    public enum Kind: Equatable, Sendable {
        case ipv4
        case ipv6
        case domain
    }

    private enum Storage: Equatable, Sendable {
        case ipv4([UInt8])
        case ipv6([UInt8])
        case domain(String)
    }

    private let storage: Storage
    public let port: UInt16

    public var kind: Kind {
        switch storage {
        case .ipv4: .ipv4
        case .ipv6: .ipv6
        case .domain: .domain
        }
    }

    public var ipBytes: [UInt8]? {
        switch storage {
        case let .ipv4(bytes), let .ipv6(bytes): bytes
        case .domain: nil
        }
    }

    public var domain: String? {
        guard case let .domain(value) = storage else { return nil }
        return value
    }

    public static func ipv4(_ bytes: [UInt8], port: UInt16) throws -> Address {
        guard bytes.count == 4 else {
            throw ProtocolCodecError.invalidAddressLength(bytes.count)
        }
        return Address(storage: .ipv4(bytes), port: port)
    }

    public static func ipv6(_ bytes: [UInt8], port: UInt16) throws -> Address {
        guard bytes.count == 16 else {
            throw ProtocolCodecError.invalidAddressLength(bytes.count)
        }
        return Address(storage: .ipv6(bytes), port: port)
    }

    public static func domain(_ domain: String, port: UInt16) throws -> Address {
        let length = domain.utf8.count
        guard (1...253).contains(length) else {
            throw ProtocolCodecError.invalidDomainLength(length)
        }
        return Address(storage: .domain(domain), port: port)
    }

    public func encoded() throws -> Data {
        var writer = ByteWriter()
        encode(into: &writer)
        return writer.data
    }

    public static func decode(_ data: Data, requireNonZeroPort: Bool = false) throws -> Address {
        var reader = ByteReader(data)
        let address = try decode(from: &reader, requireNonZeroPort: requireNonZeroPort)
        try reader.requireEnd()
        return address
    }

    func encode(into writer: inout ByteWriter) {
        switch storage {
        case let .ipv4(bytes):
            writer.append(UInt8(1))
            writer.append(contentsOf: bytes)
        case let .ipv6(bytes):
            writer.append(UInt8(2))
            writer.append(contentsOf: bytes)
        case let .domain(domain):
            let bytes = Array(domain.utf8)
            writer.append(UInt8(3))
            writer.append(UInt8(bytes.count))
            writer.append(contentsOf: bytes)
        }
        writer.append(port)
    }

    static func decode(from reader: inout ByteReader, requireNonZeroPort: Bool) throws -> Address {
        let type = try reader.readUInt8()
        let storage: Storage
        switch type {
        case 1:
            storage = .ipv4(try reader.readBytes(count: 4))
        case 2:
            storage = .ipv6(try reader.readBytes(count: 16))
        case 3:
            let length = Int(try reader.readUInt8())
            guard (1...253).contains(length) else {
                throw ProtocolCodecError.invalidDomainLength(length)
            }
            let bytes = try reader.readBytes(count: length)
            guard let domain = String(bytes: bytes, encoding: .utf8) else {
                throw ProtocolCodecError.invalidUTF8
            }
            storage = .domain(domain)
        default:
            throw ProtocolCodecError.unknownAddressType(type)
        }

        let port = try reader.readUInt16()
        if requireNonZeroPort, port == 0 { throw ProtocolCodecError.zeroPort }
        return Address(storage: storage, port: port)
    }

    public var description: String {
        switch storage {
        case let .ipv4(bytes):
            return "\(bytes.map(String.init).joined(separator: ".")):\(port)"
        case let .ipv6(bytes):
            let groups = stride(from: 0, to: 16, by: 2).map {
                String(UInt16(bytes[$0]) << 8 | UInt16(bytes[$0 + 1]), radix: 16)
            }
            return "[\(groups.joined(separator: ":"))]:\(port)"
        case let .domain(domain):
            return "\(domain):\(port)"
        }
    }
}
