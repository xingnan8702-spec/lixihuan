import Foundation
import XCTest
@testable import IPadProxyCore

private struct SharedProtocolFixture: Decodable {
    let version: Int
    let tokenHex: String
    let vectors: [SharedProtocolVector]
}

private struct SharedProtocolVector: Decodable {
    let name: String
    let kind: String
    let domain: String?
    let host: String?
    let port: UInt16?
    let message: String?
    let payloadHex: String?
    let wireHex: String
}

final class SharedProtocolFixtureTests: XCTestCase {
    func testSharedProtocolV1GoldenVectorsDecodeAndEncodeExactly() throws {
        let fixture = try loadFixture()
        XCTAssertEqual(fixture.version, 1)
        let tokenData = try decodeHex(fixture.tokenHex)
        let token = try AuthenticationToken(tokenData)

        for vector in fixture.vectors {
            let wire = try decodeHex(vector.wireHex)
            let encoded: Data
            switch vector.kind {
            case "request_udp":
                let request = try Request.decodeFrame(wire)
                XCTAssertEqual(request.command, .udpAssociate, vector.name)
                XCTAssertEqual(request.token, token, vector.name)
                XCTAssertNil(request.target, vector.name)
                encoded = try request.encodedFrame()

            case "request_tcp_domain":
                let request = try Request.decodeFrame(wire)
                XCTAssertEqual(request.command, .tcpConnect, vector.name)
                XCTAssertEqual(request.token, token, vector.name)
                XCTAssertEqual(request.target?.domain, vector.domain, vector.name)
                XCTAssertEqual(request.target?.port, vector.port, vector.name)
                encoded = try request.encodedFrame()

            case "response_ok":
                let response = try Response.decodeFrame(wire)
                XCTAssertEqual(response.status, .ok, vector.name)
                XCTAssertEqual(response.message, vector.message ?? "", vector.name)
                encoded = try response.encodedFrame()

            case "response_forbidden":
                let response = try Response.decodeFrame(wire)
                XCTAssertEqual(response.status, .forbidden, vector.name)
                XCTAssertEqual(response.message, vector.message, vector.name)
                encoded = try response.encodedFrame()

            case "datagram_ipv4", "datagram_ipv6", "datagram_domain":
                let datagram = try Datagram.decodeFrame(wire)
                XCTAssertEqual(datagram.target.port, vector.port, vector.name)
                XCTAssertEqual(datagram.payload, try decodeHex(vector.payloadHex ?? ""), vector.name)
                if let domain = vector.domain {
                    XCTAssertEqual(datagram.target.domain, domain, vector.name)
                } else if let host = vector.host {
                    let normalizedHost = try IPAddress(host).description
                    XCTAssertEqual(
                        datagram.target.description,
                        formatted(host: normalizedHost, port: vector.port!),
                        vector.name
                    )
                }
                encoded = try datagram.encodedFrame()

            default:
                XCTFail("Unknown fixture kind \(vector.kind)")
                continue
            }
            XCTAssertEqual(encoded, wire, vector.name)
        }
    }

    private func loadFixture() throws -> SharedProtocolFixture {
        let source = URL(fileURLWithPath: #filePath)
        let repository = source
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let url = repository.appendingPathComponent("testdata/protocol-v1.json")
        return try JSONDecoder().decode(SharedProtocolFixture.self, from: Data(contentsOf: url))
    }

    private func decodeHex(_ value: String) throws -> Data {
        guard value.count.isMultiple(of: 2) else { throw FixtureError.invalidHex }
        var output = Data()
        output.reserveCapacity(value.count / 2)
        var index = value.startIndex
        while index < value.endIndex {
            let next = value.index(index, offsetBy: 2)
            guard let byte = UInt8(value[index..<next], radix: 16) else {
                throw FixtureError.invalidHex
            }
            output.append(byte)
            index = next
        }
        return output
    }

    private func formatted(host: String, port: UInt16) -> String {
        host.contains(":") ? "[\(host)]:\(port)" : "\(host):\(port)"
    }

    private enum FixtureError: Error {
        case invalidHex
    }
}
