import Foundation
import XCTest
@testable import IPadProxyCore

final class DNSProxyCoreTests: XCTestCase, @unchecked Sendable {
    func testProxySynthesizesAAndAAAAPreservingIDAndRD() async throws {
        let core = try makeCore(final: .proxy)
        for (type, expectedLength) in [(UInt16(1), 4), (UInt16(28), 16)] {
            let query = dnsQuery(name: "Example.COM", type: type, id: 0x1234, recursionDesired: true)
            guard case let .respond(response) = try await core.handleQuery(query) else {
                return XCTFail("expected response")
            }
            let bytes = [UInt8](response)
            XCTAssertEqual(Array(bytes[0...1]), [0x12, 0x34])
            XCTAssertEqual(bytes[2] & 0x81, 0x81)
            XCTAssertEqual(Array(bytes[6...7]), [0, 1])
            XCTAssertEqual(Int(bytes[bytes.count - expectedLength - 2]) << 8 | Int(bytes[bytes.count - expectedLength - 1]), expectedLength)
            XCTAssertEqual(Array(bytes[(bytes.count - expectedLength - 6)..<(bytes.count - expectedLength - 2)]), [0, 0, 1, 44])
            XCTAssertEqual(response.count > query.count, true)
        }
    }

    func testDirectForwardsOriginalAndRejectReturnsRefused() async throws {
        let directCore = try makeCore(final: .direct)
        let query = dnsQuery(name: "direct.example", type: 1)
        let decision = try await directCore.handleQuery(query)
        XCTAssertEqual(decision, .forward(query, action: .direct))

        let rejectCore = try makeCore(final: .reject)
        guard case let .respond(response) = try await rejectCore.handleQuery(query) else {
            return XCTFail("expected response")
        }
        XCTAssertEqual([UInt8](response)[3] & 0x0f, 5)
        XCTAssertEqual(Array([UInt8](response)[6...7]), [0, 0])
    }

    func testUnsupportedHTTPSQueryIsForwardedEvenWhenRuleSaysProxy() async throws {
        let core = try makeCore(final: .proxy)
        let query = dnsQuery(name: "svc.example", type: 65)
        let decision = try await core.handleQuery(query)
        XCTAssertEqual(decision, .forward(query, action: .proxy))
    }

    func testQuestionCompressionPointerCannotReferenceHeader() async throws {
        let core = try makeCore(final: .direct)
        let query = Data([0x01, 0x61, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0,
                          0xc0, 0x00, 0, 1, 0, 1])
        await XCTAssertThrowsErrorAsync(try await core.handleQuery(query))
    }

    func testMalformedQueriesThrowWithoutCrashing() async throws {
        let core = try makeCore(final: .proxy)
        await XCTAssertThrowsErrorAsync(try await core.handleQuery(Data([0, 1])))
        let loop = Data([0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0,
                         0xc0, 0x0c, 0, 1, 0, 1])
        await XCTAssertThrowsErrorAsync(try await core.handleQuery(loop))
        let outOfBounds = Data([0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0,
                                0xff, 0xff, 0, 1, 0, 1])
        await XCTAssertThrowsErrorAsync(try await core.handleQuery(outOfBounds))
        var multiple = dnsQuery(name: "a.example", type: 1)
        multiple[5] = 2
        await XCTAssertThrowsErrorAsync(try await core.handleQuery(multiple))
    }

    func testTCPFramingRoundTripAndBounds() async throws {
        let query = dnsQuery(name: "tcp.example", type: 28)
        let frame = try DNSProxyCore.encodeTCPFrame(query)
        XCTAssertEqual(try DNSProxyCore.decodeTCPFrame(frame), query)
        XCTAssertThrowsError(try DNSProxyCore.decodeTCPFrame(frame + Data([0])))

        let core = try makeCore(final: .direct)
        guard case let .forward(forwarded, action) = try await core.handleTCPFrame(frame) else {
            return XCTFail("expected forward")
        }
        XCTAssertEqual(forwarded, frame)
        XCTAssertEqual(action, .direct)
    }

    private func makeCore(final: RoutingAction) throws -> DNSProxyCore {
        let configuration = try RoutingConfiguration(rules: [], final: final)
        return DNSProxyCore(
            ruleEngine: try RuleEngine(configuration: configuration),
            fakeIPStore: FakeIPStore()
        )
    }

    private func dnsQuery(
        name: String,
        type: UInt16,
        id: UInt16 = 0xabcd,
        recursionDesired: Bool = false
    ) -> Data {
        var bytes: [UInt8] = [UInt8(id >> 8), UInt8(id & 0xff), recursionDesired ? 1 : 0, 0,
                              0, 1, 0, 0, 0, 0, 0, 0]
        for label in name.split(separator: ".") {
            bytes.append(UInt8(label.utf8.count))
            bytes.append(contentsOf: label.utf8)
        }
        bytes.append(0)
        bytes.append(UInt8(type >> 8))
        bytes.append(UInt8(type & 0xff))
        bytes.append(contentsOf: [0, 1])
        return Data(bytes)
    }
}

func XCTAssertThrowsErrorAsync<T>(
    _ expression: @autoclosure () async throws -> T,
    file: StaticString = #filePath,
    line: UInt = #line
) async {
    do {
        _ = try await expression()
        XCTFail("expected error", file: file, line: line)
    } catch {}
}

extension DNSProxyCoreTests {
    func testEDNSQueryIsAcceptedAndPreservedWhenForwarded() async throws {
        var query = dnsQuery(name: "edns.example", type: 1)
        query[11] = 1
        query.append(contentsOf: [
            0,             // root owner name
            0, 41,         // OPT
            4, 208,        // UDP payload size 1232
            0, 0, 0, 0,    // extended rcode, version, flags
            0, 0,          // empty option data
        ])
        let core = try makeCore(final: .direct)
        let decision = try await core.handleQuery(query)
        XCTAssertEqual(decision, .forward(query, action: .direct))
    }
}
