import Foundation
import XCTest
@testable import IPadProxyCore

final class ProtocolCodecTests: XCTestCase {
    private let tokenBytes = Data((0..<32).map(UInt8.init))

    func testAddressRoundTripsIPv4IPv6AndUTF8Domain() throws {
        let addresses = [
            try Address.ipv4([192, 0, 2, 1], port: 443),
            try Address.ipv6(Array(repeating: 0, count: 15) + [1], port: 53),
            try Address.domain("例子.example", port: 8443),
        ]
        for address in addresses {
            XCTAssertEqual(try Address.decode(address.encoded()), address)
        }
    }

    func testAddressDomainLimitsAndInvalidUTF8AreRejected() throws {
        let maximum = String(repeating: "a", count: 253)
        XCTAssertEqual(try Address.domain(maximum, port: 1).domain, maximum)
        XCTAssertThrowsError(try Address.domain("", port: 1))
        XCTAssertThrowsError(try Address.domain(String(repeating: "a", count: 254), port: 1))
        XCTAssertThrowsError(try Address.decode(Data([3, 1, 0xff, 0, 80]))) { error in
            XCTAssertEqual(error as? ProtocolCodecError, .invalidUTF8)
        }
    }

    func testAddressRejectsUnknownTypeTruncationAndTrailingBytes() throws {
        XCTAssertThrowsError(try Address.decode(Data([9, 0, 1])))
        XCTAssertThrowsError(try Address.decode(Data([1, 127, 0, 0, 1, 0])))
        let address = try Address.ipv4([127, 0, 0, 1], port: 80).encoded() + Data([0])
        XCTAssertThrowsError(try Address.decode(address)) { error in
            XCTAssertEqual(error as? ProtocolCodecError, .trailingBytes(1))
        }
    }

    func testFrameRejectsZeroOversizedTruncatedAndTrailingData() throws {
        XCTAssertThrowsError(try FrameCodec.decode(Data([0, 0, 0, 0])))
        XCTAssertThrowsError(try FrameCodec.decode(Data([0, 1, 0, 65]))) { error in
            XCTAssertEqual(error as? ProtocolCodecError, .frameTooLarge(65_601))
        }
        XCTAssertThrowsError(try FrameCodec.decode(Data([0, 0, 0, 2, 1])))
        XCTAssertThrowsError(try FrameCodec.decode(Data([0, 0, 0, 1, 1, 2])))
        XCTAssertThrowsError(try FrameCodec.encode(body: Data()))
        XCTAssertEqual(try FrameCodec.decode(FrameCodec.encode(body: Data([7]))), Data([7]))
    }

    func testUDPAssociateGoldenFrameAndRoundTrip() throws {
        let token = try AuthenticationToken(tokenBytes)
        let request = try Request.udpAssociate(token: token)
        let frame = try request.encodedFrame()
        XCTAssertEqual(Array(frame.prefix(4)), [0, 0, 0, 35])
        XCTAssertEqual(Array(frame[4...6]), [1, 2, 32])
        XCTAssertEqual(try Request.decodeFrame(frame), request)
    }

    func testTCPRequestRoundTripAndPortValidation() throws {
        let token = try AuthenticationToken(tokenBytes)
        let target = try Address.domain("Example.COM.", port: 443)
        let request = try Request.tcpConnect(token: token, target: target)
        XCTAssertEqual(try Request.decodeFrame(request.encodedFrame()), request)

        let zeroPort = try Address.ipv4([192, 0, 2, 1], port: 0)
        XCTAssertThrowsError(try Request.tcpConnect(token: token, target: zeroPort)) { error in
            XCTAssertEqual(error as? ProtocolCodecError, .zeroPort)
        }
    }

    func testRequestRejectsInvalidTokenVersionCommandAndTrailingTarget() throws {
        XCTAssertThrowsError(try AuthenticationToken(Data(repeating: 0, count: 31)))
        XCTAssertThrowsError(try Request.decodeBody(Data([2, 2, 32]) + tokenBytes))
        XCTAssertThrowsError(try Request.decodeBody(Data([1, 9, 32]) + tokenBytes))
        XCTAssertThrowsError(try Request.decodeBody(Data([1, 2, 31]) + Data(repeating: 0, count: 31)))
        XCTAssertThrowsError(try Request.decodeBody(Data([1, 2, 32]) + tokenBytes + Data([0]))) { error in
            XCTAssertEqual(error as? ProtocolCodecError, .trailingBytes(1))
        }
    }

    func testResponseGoldenFrameAndStrictValidation() throws {
        let response = try Response(status: .ok, message: "")
        XCTAssertEqual(Array(try response.encodedFrame()), [0, 0, 0, 4, 1, 0, 0, 0])
        XCTAssertEqual(try Response.decodeFrame(response.encodedFrame()), response)

        XCTAssertNoThrow(try Response(status: .internalError, message: String(repeating: "a", count: 512)))
        XCTAssertThrowsError(try Response(status: .ok, message: String(repeating: "a", count: 513)))
        XCTAssertThrowsError(try Response.decodeBody(Data([1, 6, 0, 0])))
        XCTAssertThrowsError(try Response.decodeBody(Data([1, 0, 0, 1, 0xff])))
        XCTAssertThrowsError(try Response.decodeBody(Data([1, 0, 0, 0, 1])))
    }

    func testDatagramRoundTripAndCombinedSizeLimits() throws {
        let ipv4 = try Address.ipv4([203, 0, 113, 1], port: 53)
        let largestProtocolPayload = Data(repeating: 7, count: Datagram.maximumPayloadLength)
        let datagram = try Datagram(target: ipv4, payload: largestProtocolPayload)
        XCTAssertEqual(try Datagram.decodeFrame(datagram.encodedFrame()), datagram)

        let domain = try Address.domain(String(repeating: "a", count: 253), port: 53)
        let largestFramedPayload = Data(repeating: 1, count: 65_342)
        XCTAssertNoThrow(try Datagram(target: domain, payload: largestFramedPayload).encodedFrame())
        XCTAssertThrowsError(try Datagram(target: domain, payload: largestFramedPayload + Data([1])).encodedFrame()) {
            error in
            XCTAssertEqual(error as? ProtocolCodecError, .frameTooLarge(65_601))
        }
        XCTAssertThrowsError(try Datagram(target: ipv4, payload: Data(repeating: 0, count: 65_508)))
    }

    func testDatagramAllowsEmptyPayloadButRejectsZeroPort() throws {
        let target = try Address.ipv6(Array(repeating: 0, count: 16), port: 1)
        let datagram = try Datagram(target: target, payload: Data())
        XCTAssertEqual(try Datagram.decodeBody(datagram.encodedBody()).payload, Data())
        XCTAssertThrowsError(
            try Datagram(target: Address.ipv4([1, 1, 1, 1], port: 0), payload: Data())
        )
    }

    func testSensitiveDescriptionsAreRedacted() throws {
        let token = try AuthenticationToken(Data(repeating: 0xab, count: 32))
        let request = try Request.udpAssociate(token: token)
        XCTAssertEqual(String(describing: token), "<redacted 256-bit token>")
        XCTAssertTrue(String(describing: request).contains("<redacted>"))
        XCTAssertFalse(String(reflecting: request).contains("171"))
    }
}
