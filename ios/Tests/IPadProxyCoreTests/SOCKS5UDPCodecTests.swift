import Foundation
import XCTest
@testable import IPadProxyCore

final class SOCKS5UDPCodecTests: XCTestCase {
    func testExactIPv4IPv6AndDomainDatagramsRoundTrip() throws {
        let cases: [(Address, Data, Data)] = [
            (
                try Address.ipv4([192, 0, 2, 9], port: 53),
                Data([1, 2, 3]),
                Data([0, 0, 0, 1, 192, 0, 2, 9, 0, 53, 1, 2, 3])
            ),
            (
                try Address.ipv6(Array(0...15), port: 4_433),
                Data([0xaa]),
                Data([0, 0, 0, 4] + Array(0...15) + [0x11, 0x51, 0xaa])
            ),
            (
                try Address.domain("dns.example", port: 853),
                Data([0xde, 0xad]),
                Data([0, 0, 0, 3, 11] + Array("dns.example".utf8) + [0x03, 0x55, 0xde, 0xad])
            ),
        ]

        for (target, payload, wire) in cases {
            let datagram = try SOCKS5UDPDatagram(target: target, payload: payload)
            XCTAssertEqual(try SOCKS5UDPDatagramCodec.encode(datagram), wire)
            XCTAssertEqual(try SOCKS5UDPDatagramCodec.decode(wire), datagram)
        }
    }

    func testEmptyPayloadIsPreserved() throws {
        let datagram = try SOCKS5UDPDatagram(
            target: Address.ipv4([127, 0, 0, 1], port: 1),
            payload: Data()
        )
        let wire = Data([0, 0, 0, 1, 127, 0, 0, 1, 0, 1])
        XCTAssertEqual(try SOCKS5UDPDatagramCodec.encode(datagram), wire)
        XCTAssertEqual(try SOCKS5UDPDatagramCodec.decode(wire), datagram)
    }

    func testRejectsReservedFragmentAddressTypeAndZeroPort() {
        assertDecodeError([0, 1, 0, 1, 127, 0, 0, 1, 0, 1], .invalidUDPReserved(1))
        assertDecodeError([0, 0, 1, 1, 127, 0, 0, 1, 0, 1], .unsupportedUDPFragment(1))
        assertDecodeError([0, 0, 0, 2, 0, 1], .unknownAddressType(2))
        assertDecodeError([0, 0, 0, 1, 127, 0, 0, 1, 0, 0], .zeroPort)
    }

    func testRejectsTruncatedDatagramsAndInvalidDomain() {
        for bytes: [UInt8] in [
            [], [0], [0, 0], [0, 0, 0],
            [0, 0, 0, 1], [0, 0, 0, 1, 127, 0, 0, 1, 0],
            [0, 0, 0, 4, 0, 1],
            [0, 0, 0, 3], [0, 0, 0, 3, 1], [0, 0, 0, 3, 1, 0x61, 0],
        ] {
            assertDecodeError(bytes, .truncatedUDPDatagram)
        }
        assertDecodeError([0, 0, 0, 3, 0], .invalidDomainLength(0))
        assertDecodeError([0, 0, 0, 3, 1, 0xff, 0, 1], .invalidUTF8)
    }

    func testMaximumDatagramBoundaryAndOversize() throws {
        let target = try Address.ipv4([127, 0, 0, 1], port: 53)
        let headerLength = 10
        let maximum = try SOCKS5UDPDatagram(
            target: target,
            payload: Data(repeating: 0xab, count: SOCKS5UDPDatagramCodec.maximumDatagramLength - headerLength)
        )
        XCTAssertEqual(
            try SOCKS5UDPDatagramCodec.encode(maximum).count,
            SOCKS5UDPDatagramCodec.maximumDatagramLength
        )

        let oversize = try SOCKS5UDPDatagram(
            target: target,
            payload: Data(repeating: 0xab, count: SOCKS5UDPDatagramCodec.maximumDatagramLength - headerLength + 1)
        )
        XCTAssertThrowsError(try SOCKS5UDPDatagramCodec.encode(oversize)) {
            XCTAssertEqual(
                $0 as? SOCKS5CodecError,
                .udpDatagramTooLarge(SOCKS5UDPDatagramCodec.maximumDatagramLength + 1)
            )
        }
        XCTAssertThrowsError(
            try SOCKS5UDPDatagramCodec.decode(
                Data(repeating: 0, count: SOCKS5UDPDatagramCodec.maximumDatagramLength + 1)
            )
        ) {
            XCTAssertEqual(
                $0 as? SOCKS5CodecError,
                .udpDatagramTooLarge(SOCKS5UDPDatagramCodec.maximumDatagramLength + 1)
            )
        }
    }

    func testUDPAssociateControlAllowsUnspecifiedIPv4AndIPv6ButConnectDoesNot() throws {
        let cases: [(Address, Data)] = [
            (
                try Address.ipv4([0, 0, 0, 0], port: 0),
                Data([0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            ),
            (
                try Address.ipv6(Array(repeating: 0, count: 16), port: 0),
                Data([0x05, 0x03, 0x00, 0x04] + Array(repeating: 0, count: 18))
            ),
        ]
        for (address, wire) in cases {
            let request = SOCKS5Request(command: .udpAssociate, destination: address)
            XCTAssertEqual(try SOCKS5Codec.encodeRequest(request), wire)
            XCTAssertEqual(try SOCKS5Codec.parseRequest(wire), .complete(request, remainder: Data()))
        }

        let connect = SOCKS5Request(
            command: .connect,
            destination: try Address.ipv4([0, 0, 0, 0], port: 0)
        )
        XCTAssertThrowsError(try SOCKS5Codec.encodeRequest(connect)) {
            XCTAssertEqual($0 as? SOCKS5CodecError, .zeroPort)
        }

        for invalid in [
            SOCKS5Request(
                command: .udpAssociate,
                destination: try Address.ipv4([127, 0, 0, 1], port: 0)
            ),
            SOCKS5Request(
                command: .udpAssociate,
                destination: try Address.domain("client.example", port: 0)
            ),
        ] {
            XCTAssertThrowsError(try SOCKS5Codec.encodeRequest(invalid)) {
                XCTAssertEqual($0 as? SOCKS5CodecError, .zeroPort)
            }
        }
        XCTAssertThrowsError(
            try SOCKS5Codec.parseRequest(
                Data([0x05, 0x03, 0x00, 0x01, 127, 0, 0, 1, 0, 0])
            )
        ) {
            XCTAssertEqual($0 as? SOCKS5CodecError, .zeroPort)
        }
    }

    private func assertDecodeError(
        _ bytes: [UInt8],
        _ expected: SOCKS5CodecError,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        XCTAssertThrowsError(try SOCKS5UDPDatagramCodec.decode(Data(bytes)), file: file, line: line) {
            XCTAssertEqual($0 as? SOCKS5CodecError, expected, file: file, line: line)
        }
    }
}
