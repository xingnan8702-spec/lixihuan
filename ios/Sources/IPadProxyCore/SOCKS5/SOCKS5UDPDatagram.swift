import Foundation

/// One RFC 1928 SOCKS5 UDP request or response datagram.
public struct SOCKS5UDPDatagram: Equatable, Sendable {
    public let target: Address
    public let payload: Data

    public init(target: Address, payload: Data) throws {
        guard target.port != 0 else { throw SOCKS5CodecError.zeroPort }
        self.target = target
        self.payload = payload
    }
}

/// Strict datagram-boundary codec for the SOCKS5 UDP relay header.
/// Fragmentation is deliberately unsupported; FRAG must be zero.
public enum SOCKS5UDPDatagramCodec {
    /// Conservative maximum UDP payload that avoids exceeding the IPv4 UDP limit.
    public static let maximumDatagramLength = 65_507

    public static func decode(_ data: Data) throws -> SOCKS5UDPDatagram {
        guard data.count <= maximumDatagramLength else {
            throw SOCKS5CodecError.udpDatagramTooLarge(data.count)
        }
        let bytes = [UInt8](data)
        guard bytes.count >= 4 else { throw SOCKS5CodecError.truncatedUDPDatagram }
        let reserved = UInt16(bytes[0]) << 8 | UInt16(bytes[1])
        guard reserved == 0 else { throw SOCKS5CodecError.invalidUDPReserved(reserved) }
        guard bytes[2] == 0 else { throw SOCKS5CodecError.unsupportedUDPFragment(bytes[2]) }

        var cursor = 4
        let target: Address
        switch bytes[3] {
        case 0x01:
            guard bytes.count >= cursor + 6 else { throw SOCKS5CodecError.truncatedUDPDatagram }
            let address = Array(bytes[cursor..<(cursor + 4)])
            cursor += 4
            let port = readPort(bytes, at: cursor)
            guard port != 0 else { throw SOCKS5CodecError.zeroPort }
            target = try Address.ipv4(address, port: port)
            cursor += 2
        case 0x04:
            guard bytes.count >= cursor + 18 else { throw SOCKS5CodecError.truncatedUDPDatagram }
            let address = Array(bytes[cursor..<(cursor + 16)])
            cursor += 16
            let port = readPort(bytes, at: cursor)
            guard port != 0 else { throw SOCKS5CodecError.zeroPort }
            target = try Address.ipv6(address, port: port)
            cursor += 2
        case 0x03:
            guard bytes.count > cursor else { throw SOCKS5CodecError.truncatedUDPDatagram }
            let length = Int(bytes[cursor])
            guard (1...SOCKS5Codec.maximumDomainLength).contains(length) else {
                throw SOCKS5CodecError.invalidDomainLength(length)
            }
            cursor += 1
            guard bytes.count >= cursor + length + 2 else {
                throw SOCKS5CodecError.truncatedUDPDatagram
            }
            guard let domain = String(bytes: bytes[cursor..<(cursor + length)], encoding: .utf8) else {
                throw SOCKS5CodecError.invalidUTF8
            }
            cursor += length
            let port = readPort(bytes, at: cursor)
            guard port != 0 else { throw SOCKS5CodecError.zeroPort }
            target = try Address.domain(domain, port: port)
            cursor += 2
        default:
            throw SOCKS5CodecError.unknownAddressType(bytes[3])
        }

        return try SOCKS5UDPDatagram(
            target: target,
            payload: Data(bytes[cursor...])
        )
    }

    public static func encode(_ datagram: SOCKS5UDPDatagram) throws -> Data {
        guard datagram.target.port != 0 else { throw SOCKS5CodecError.zeroPort }
        var result = Data([0x00, 0x00, 0x00])
        switch datagram.target.kind {
        case .ipv4:
            guard let bytes = datagram.target.ipBytes, bytes.count == 4 else {
                throw SOCKS5CodecError.unknownAddressType(0x01)
            }
            result.append(0x01)
            result.append(contentsOf: bytes)
        case .ipv6:
            guard let bytes = datagram.target.ipBytes, bytes.count == 16 else {
                throw SOCKS5CodecError.unknownAddressType(0x04)
            }
            result.append(0x04)
            result.append(contentsOf: bytes)
        case .domain:
            guard let domain = datagram.target.domain else {
                throw SOCKS5CodecError.invalidDomainLength(0)
            }
            let bytes = Array(domain.utf8)
            guard (1...SOCKS5Codec.maximumDomainLength).contains(bytes.count) else {
                throw SOCKS5CodecError.invalidDomainLength(bytes.count)
            }
            result.append(0x03)
            result.append(UInt8(bytes.count))
            result.append(contentsOf: bytes)
        }
        result.append(UInt8(datagram.target.port >> 8))
        result.append(UInt8(datagram.target.port & 0xff))
        guard result.count + datagram.payload.count <= maximumDatagramLength else {
            throw SOCKS5CodecError.udpDatagramTooLarge(result.count + datagram.payload.count)
        }
        result.append(datagram.payload)
        return result
    }

    private static func readPort(_ bytes: [UInt8], at offset: Int) -> UInt16 {
        UInt16(bytes[offset]) << 8 | UInt16(bytes[offset + 1])
    }
}
