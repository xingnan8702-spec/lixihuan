import Foundation

public enum ProtocolCodecError: Error, Equatable, Sendable {
    case truncated
    case trailingBytes(Int)
    case invalidFrameLength(Int)
    case frameTooLarge(Int)
    case unknownVersion(UInt8)
    case unknownAddressType(UInt8)
    case invalidAddressLength(Int)
    case invalidUTF8
    case invalidDomainLength(Int)
    case zeroPort
    case unknownCommand(UInt8)
    case invalidTokenLength(Int)
    case targetRequired
    case unexpectedTarget
    case unknownStatus(UInt8)
    case messageTooLong(Int)
    case payloadTooLong(Int)
}

struct ByteReader {
    private let bytes: [UInt8]
    private(set) var offset = 0

    init(_ data: Data) {
        bytes = Array(data)
    }

    var remaining: Int { bytes.count - offset }

    mutating func readUInt8() throws -> UInt8 {
        guard remaining >= 1 else { throw ProtocolCodecError.truncated }
        defer { offset += 1 }
        return bytes[offset]
    }

    mutating func readUInt16() throws -> UInt16 {
        let value = try readBytes(count: 2)
        return UInt16(value[0]) << 8 | UInt16(value[1])
    }

    mutating func readBytes(count: Int) throws -> [UInt8] {
        guard count >= 0, remaining >= count else { throw ProtocolCodecError.truncated }
        let start = offset
        offset += count
        return Array(bytes[start..<offset])
    }

    mutating func readRemaining() -> [UInt8] {
        let value = Array(bytes[offset...])
        offset = bytes.count
        return value
    }

    func requireEnd() throws {
        guard remaining == 0 else { throw ProtocolCodecError.trailingBytes(remaining) }
    }
}

struct ByteWriter {
    private(set) var bytes: [UInt8] = []

    mutating func append(_ value: UInt8) {
        bytes.append(value)
    }

    mutating func append(_ value: UInt16) {
        bytes.append(UInt8((value >> 8) & 0xff))
        bytes.append(UInt8(value & 0xff))
    }

    mutating func append(_ value: UInt32) {
        bytes.append(UInt8((value >> 24) & 0xff))
        bytes.append(UInt8((value >> 16) & 0xff))
        bytes.append(UInt8((value >> 8) & 0xff))
        bytes.append(UInt8(value & 0xff))
    }

    mutating func append(contentsOf values: [UInt8]) {
        bytes.append(contentsOf: values)
    }

    var data: Data { Data(bytes) }
}
