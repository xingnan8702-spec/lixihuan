import Foundation
import XCTest
@testable import IPadProxyCore

final class SOCKS5CodecTests: XCTestCase {
    func testGreetingHandlesEveryTruncationAndGluedRequest() throws {
        let greeting = Data([0x05, 0x02, 0x02, 0x00])
        for length in 0..<greeting.count {
            XCTAssertEqual(try SOCKS5Codec.parseGreeting(greeting.prefix(length)), .incomplete)
        }
        let glued = greeting + Data([0x05, 0x01, 0x00])
        XCTAssertEqual(
            try SOCKS5Codec.parseGreeting(glued),
            .complete(SOCKS5Greeting(methods: [0x02, 0x00]), remainder: Data([0x05, 0x01, 0x00]))
        )
        XCTAssertEqual(SOCKS5Codec.encodeNoAuthenticationSelection(), Data([0x05, 0x00]))
        XCTAssertEqual(SOCKS5Codec.encodeNoAcceptableMethodsSelection(), Data([0x05, 0xff]))
    }

    func testGreetingRejectsMissingNoAuthenticationAndWrongVersion() throws {
        XCTAssertThrowsError(try SOCKS5Codec.parseGreeting(Data([0x05, 0x01, 0x02]))) {
            XCTAssertEqual($0 as? SOCKS5CodecError, .noAuthenticationMethod)
        }
        XCTAssertThrowsError(try SOCKS5Codec.parseGreeting(Data([0x04, 0x01, 0x00]))) {
            XCTAssertEqual($0 as? SOCKS5CodecError, .invalidVersion(0x04))
        }
        XCTAssertThrowsError(try SOCKS5Codec.parseGreeting(Data([0x05, 0x00]))) {
            XCTAssertEqual($0 as? SOCKS5CodecError, .noAuthenticationMethod)
        }
    }

    func testMethodSelectionIsIncrementalAndOnlyAcceptsNoAuthentication() throws {
        XCTAssertEqual(try SOCKS5Codec.parseMethodSelection(Data([0x05])), .incomplete)
        XCTAssertEqual(
            try SOCKS5Codec.parseMethodSelection(Data([0x05, 0x00, 0xaa])),
            .complete(0x00, remainder: Data([0xaa]))
        )
        XCTAssertThrowsError(try SOCKS5Codec.parseMethodSelection(Data([0x05, 0x02]))) {
            XCTAssertEqual($0 as? SOCKS5CodecError, .unsupportedAuthenticationMethod(0x02))
        }
    }

    func testConnectIPv4IPv6AndDomainExactBytesAndRoundTrip() throws {
        let cases: [(Address, Data)] = [
            (try Address.ipv4([192, 0, 2, 7], port: 443),
             Data([0x05, 0x01, 0x00, 0x01, 192, 0, 2, 7, 0x01, 0xbb])),
            (try Address.ipv6(Array(0...15), port: 53),
             Data([0x05, 0x01, 0x00, 0x04] + Array(0...15) + [0x00, 0x35])),
            (try Address.domain("example.com", port: 8_443),
             Data([0x05, 0x01, 0x00, 0x03, 11] + Array("example.com".utf8) + [0x20, 0xfb])),
        ]

        for (address, wire) in cases {
            let request = SOCKS5Request(command: .connect, destination: address)
            XCTAssertEqual(try SOCKS5Codec.encodeRequest(request), wire)
            XCTAssertEqual(
                try SOCKS5Codec.parseRequest(wire),
                .complete(request, remainder: Data())
            )
            assertEveryPrefixIsIncomplete(wire, parser: SOCKS5Codec.parseRequest)
        }
    }

    func testRequestReturnsGluedPayloadAsRemainder() throws {
        let request = SOCKS5Request(
            command: .connect,
            destination: try Address.domain("a.example", port: 443)
        )
        let payload = Data(repeating: 0xab, count: 4_096)
        XCTAssertEqual(
            try SOCKS5Codec.parseRequest(SOCKS5Codec.encodeRequest(request) + payload),
            .complete(request, remainder: payload)
        )
    }

    func testRequestParsesUDPAssociateWithoutTreatingItAsConnect() throws {
        let udp = Data([0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 1])
        XCTAssertEqual(
            try SOCKS5Codec.parseRequest(udp),
            .complete(
                SOCKS5Request(
                    command: .udpAssociate,
                    destination: try Address.ipv4([0, 0, 0, 0], port: 1)
                ),
                remainder: Data()
            )
        )
    }

    func testRequestRejectsVersionReservedCommandAddressAndZeroPort() throws {
        let valid = [0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0, 80] as [UInt8]
        var candidate = valid
        candidate[0] = 4
        assertError(candidate, .invalidVersion(4))
        candidate = valid
        candidate[2] = 1
        assertError(candidate, .invalidReserved(1))
        candidate = valid
        candidate[1] = 2
        assertError(candidate, .unsupportedCommand(2))
        candidate = valid
        candidate[1] = 9
        assertError(candidate, .unknownCommand(9))
        candidate = valid
        candidate[3] = 2
        assertError(candidate, .unknownAddressType(2))
        candidate = valid
        candidate[8] = 0
        candidate[9] = 0
        assertError(candidate, .zeroPort)
    }

    func testDomainLengthUTF8AndMaximumControlMessageLength() throws {
        let maximum = String(repeating: "a", count: 253)
        let request = SOCKS5Request(
            command: .connect,
            destination: try Address.domain(maximum, port: 1)
        )
        let maximumWire = try SOCKS5Codec.encodeRequest(request)
        XCTAssertEqual(maximumWire.count, SOCKS5Codec.maximumControlMessageLength)
        XCTAssertNoThrow(try SOCKS5Codec.parseRequest(maximumWire))

        XCTAssertThrowsError(try SOCKS5Codec.parseRequest(Data([0x05, 0x01, 0x00, 0x03, 0x00]))) {
            XCTAssertEqual($0 as? SOCKS5CodecError, .invalidDomainLength(0))
        }
        XCTAssertThrowsError(try SOCKS5Codec.parseRequest(Data([0x05, 0x01, 0x00, 0x03, 0xfe]))) {
            XCTAssertEqual($0 as? SOCKS5CodecError, .invalidDomainLength(254))
        }
        XCTAssertThrowsError(
            try SOCKS5Codec.parseRequest(Data([0x05, 0x01, 0x00, 0x03, 0x01, 0xff, 0, 1]))
        ) {
            XCTAssertEqual($0 as? SOCKS5CodecError, .invalidUTF8)
        }
        XCTAssertThrowsError(
            try SOCKS5Codec.parseRequest(Data(repeating: 0, count: SOCKS5Codec.maximumControlMessageLength + 1))
        ) {
            XCTAssertEqual(
                $0 as? SOCKS5CodecError,
                .invalidVersion(0)
            )
        }
    }

    func testReplyExactBytesIncrementalRoundTripAndRemainder() throws {
        let bound = try Address.ipv6(Array(repeating: 0, count: 15) + [1], port: 10_080)
        let reply = try SOCKS5Reply(code: .succeeded, boundAddress: bound)
        let expected = Data(
            [0x05, 0x00, 0x00, 0x04]
                + Array(repeating: 0, count: 15)
                + [1, 0x27, 0x60]
        )
        XCTAssertEqual(try SOCKS5Codec.encodeReply(reply), expected)
        assertEveryPrefixIsIncomplete(expected, parser: SOCKS5Codec.parseReply)
        XCTAssertEqual(
            try SOCKS5Codec.parseReply(expected + Data([1, 2, 3])),
            .complete(reply, remainder: Data([1, 2, 3]))
        )
    }

    func testReplyRejectsUnknownCodeReservedAndAddressType() throws {
        XCTAssertThrowsError(
            try SOCKS5Codec.parseReply(Data([0x05, 0x09, 0x00, 0x01, 0, 0, 0, 0, 0, 1]))
        ) {
            XCTAssertEqual($0 as? SOCKS5CodecError, .unknownReply(9))
        }
        XCTAssertThrowsError(
            try SOCKS5Codec.parseReply(Data([0x05, 0x00, 0x01, 0x01, 0, 0, 0, 0, 0, 1]))
        ) {
            XCTAssertEqual($0 as? SOCKS5CodecError, .invalidReserved(1))
        }
        XCTAssertThrowsError(
            try SOCKS5Codec.parseReply(Data([0x05, 0x00, 0x00, 0x02, 0, 1]))
        ) {
            XCTAssertEqual($0 as? SOCKS5CodecError, .unknownAddressType(2))
        }
    }

    func testReplyAllowsUnspecifiedIPv4AddressAndZeroPortExactBytes() throws {
        let expected = Data([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        let reply = try SOCKS5Reply(
            code: .succeeded,
            boundAddress: Address.ipv4([0, 0, 0, 0], port: 0)
        )

        XCTAssertEqual(try SOCKS5Codec.encodeReply(reply), expected)
        XCTAssertEqual(try SOCKS5Codec.encodeUnspecifiedReply(.succeeded), expected)
        assertEveryPrefixIsIncomplete(expected, parser: SOCKS5Codec.parseReply)
        XCTAssertEqual(
            try SOCKS5Codec.parseReply(expected),
            .complete(reply, remainder: Data())
        )
    }

    func testUnsupportedAndUnknownCommandsMapToREP07ExactBytes() throws {
        let expected = Data([0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        for command: UInt8 in [0x02, 0x09] {
            let request = Data([0x05, command, 0x00, 0x01, 127, 0, 0, 1, 0, 80])
            do {
                _ = try SOCKS5Codec.parseRequest(request)
                XCTFail("command \(command) must be rejected")
            } catch let error as SOCKS5CodecError {
                let code = SOCKS5Codec.replyCode(forRequestError: error)
                XCTAssertEqual(code, .commandNotSupported)
                XCTAssertEqual(try SOCKS5Codec.encodeUnspecifiedReply(code), expected)
            }
        }
    }

    func testZeroPortRequestStillRejected() throws {
        let request = Data([0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        XCTAssertThrowsError(try SOCKS5Codec.parseRequest(request)) {
            XCTAssertEqual($0 as? SOCKS5CodecError, .zeroPort)
        }
        XCTAssertThrowsError(
            try SOCKS5Codec.encodeRequest(SOCKS5Request(
                command: .connect,
                destination: Address.ipv4([0, 0, 0, 0], port: 0)
            ))
        ) {
            XCTAssertEqual($0 as? SOCKS5CodecError, .zeroPort)
        }
    }

    private func assertEveryPrefixIsIncomplete<Value: Equatable & Sendable>(
        _ wire: Data,
        parser: (Data) throws -> SOCKS5ParseResult<Value>,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        for length in 0..<wire.count {
            XCTAssertEqual(
                try parser(Data(wire.prefix(length))),
                .incomplete,
                "prefix length \(length)",
                file: file,
                line: line
            )
        }
    }

    private func assertError(
        _ bytes: [UInt8],
        _ expected: SOCKS5CodecError,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        XCTAssertThrowsError(try SOCKS5Codec.parseRequest(Data(bytes)), file: file, line: line) {
            XCTAssertEqual($0 as? SOCKS5CodecError, expected, file: file, line: line)
        }
    }
}
