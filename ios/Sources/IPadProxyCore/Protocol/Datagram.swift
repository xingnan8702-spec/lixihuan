import Foundation

public struct Datagram: Equatable, Sendable {
    public static let maximumPayloadLength = 65_507

    public let target: Address
    public let payload: Data

    public init(target: Address, payload: Data) throws {
        guard target.port != 0 else { throw ProtocolCodecError.zeroPort }
        guard payload.count <= Self.maximumPayloadLength else {
            throw ProtocolCodecError.payloadTooLong(payload.count)
        }
        self.target = target
        self.payload = payload
    }

    public func encodedBody() throws -> Data {
        guard payload.count <= Self.maximumPayloadLength else {
            throw ProtocolCodecError.payloadTooLong(payload.count)
        }
        var writer = ByteWriter()
        writer.append(UInt8(1))
        target.encode(into: &writer)
        writer.append(contentsOf: Array(payload))
        let body = writer.data
        guard body.count <= FrameCodec.maximumBodyLength else {
            throw ProtocolCodecError.frameTooLarge(body.count)
        }
        return body
    }

    public func encodedFrame() throws -> Data {
        try FrameCodec.encode(body: encodedBody())
    }

    public static func decodeBody(_ body: Data) throws -> Datagram {
        var reader = ByteReader(body)
        let version = try reader.readUInt8()
        guard version == 1 else { throw ProtocolCodecError.unknownVersion(version) }
        let target = try Address.decode(from: &reader, requireNonZeroPort: true)
        let payload = Data(reader.readRemaining())
        return try Datagram(target: target, payload: payload)
    }

    public static func decodeFrame(_ frame: Data) throws -> Datagram {
        try decodeBody(FrameCodec.decode(frame))
    }
}
