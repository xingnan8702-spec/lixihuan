import Foundation
import XCTest
@testable import IPadProxyCore

final class FlowRouterTransportTests: XCTestCase, @unchecked Sendable {
    func testProxyFailureNeverFallsBackToDirect() async throws {
        let direct = RecordingTransport()
        let proxy = RecordingTransport(.fail)
        let engine = try RuleEngine(configuration: RoutingConfiguration(rules: [], final: .proxy))
        let router = FlowRouter(engine: engine, directTransport: direct, proxyTransport: proxy)
        let destination = try RoutingDestination(domain: "example.com", port: 443)
        let target = try Address.domain("example.com", port: 443)

        do {
            _ = try await router.routeTCP(destination: destination, target: target)
            XCTFail("expected proxy failure")
        } catch {
            XCTAssertEqual(error as? TestTransportFailure, .openFailed)
        }
        let directCounts = await direct.counts()
        let proxyCounts = await proxy.counts()
        XCTAssertEqual(directCounts.tcp, 0)
        XCTAssertEqual(proxyCounts.tcp, 1)
    }

    func testDirectProxyAndRejectAreExplicit() async throws {
        let direct = RecordingTransport()
        let proxy = RecordingTransport()
        let rules = [try RoutingRule(type: .port, value: "53", action: .direct)]
        let engine = try RuleEngine(configuration: RoutingConfiguration(rules: rules, final: .reject))
        let router = FlowRouter(engine: engine, directTransport: direct, proxyTransport: proxy)

        let dnsTarget = try Address.domain("dns.example", port: 53)
        _ = try await router.routeUDP(
            destination: RoutingDestination(domain: "dns.example", port: 53),
            target: dnsTarget
        )
        do {
            _ = try await router.routeUDP(
                destination: RoutingDestination(domain: "blocked.example", port: 443),
                target: try Address.domain("blocked.example", port: 443)
            )
            XCTFail("expected rejection")
        } catch {
            XCTAssertEqual(error as? FlowRouterError, .rejected)
        }
        let directCounts = await direct.counts()
        let proxyCounts = await proxy.counts()
        XCTAssertEqual(directCounts.udp, 1)
        XCTAssertEqual(proxyCounts.udp, 0)
    }

    func testTransportDoublesAreBoundedAndModelHalfClose() async throws {
        let stream = TestTCPByteStream(byteLimit: 3)
        try await stream.send(Data([1, 2, 3]))
        await XCTAssertThrowsErrorAsync(try await stream.send(Data([4])))
        try await stream.finishSending()
        let finished = await stream.didFinishSending
        XCTAssertTrue(finished)
        await stream.close()
        await XCTAssertThrowsErrorAsync(try await stream.send(Data()))

        let association = TestUDPAssociation(datagramLimit: 1)
        try await association.send(Data())
        await XCTAssertThrowsErrorAsync(try await association.send(Data()))
    }

    func testMemoryCredentialStoreExistsOnlyInTests() async throws {
        let store = InMemoryCredentialStore()
        let token = try AuthenticationToken(Data(repeating: 7, count: 32))
        try await store.saveAuthenticationToken(token)
        let loaded = try await store.loadAuthenticationToken()
        XCTAssertEqual(loaded, token)
        try await store.deleteAuthenticationToken()
        await XCTAssertThrowsErrorAsync(try await store.loadAuthenticationToken())
    }
}
