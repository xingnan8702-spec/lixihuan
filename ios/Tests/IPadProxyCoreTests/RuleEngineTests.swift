import Foundation
import XCTest
@testable import IPadProxyCore

final class RuleEngineTests: XCTestCase {
    func testConfigurationDecodesSchemaAndFirstMatchWins() throws {
        let json = Data(#"{"version":1,"generatedAt":"2026-10-31T00:00:00Z","rules":[{"type":"domain_suffix","value":"Example.COM.","action":"DIRECT"},{"type":"domain","value":"www.example.com","action":"REJECT"}],"final":"PROXY"}"#.utf8)
        let configuration = try RoutingConfiguration.decode(from: json)
        let engine = try RuleEngine(configuration: configuration)
        let destination = try RoutingDestination(domain: "WWW.Example.Com.", port: 443)
        XCTAssertEqual(engine.action(for: destination), .direct)
    }

    func testDomainSuffixUsesLabelBoundaryAndIncludesApex() throws {
        let rule = try RoutingRule(type: .domainSuffix, value: "example.com.", action: .direct)
        let engine = try RuleEngine(configuration: RoutingConfiguration(rules: [rule], final: .proxy))
        XCTAssertEqual(engine.action(for: try RoutingDestination(domain: "example.com", port: 443)), .direct)
        XCTAssertEqual(engine.action(for: try RoutingDestination(domain: "a.Example.Com.", port: 443)), .direct)
        XCTAssertEqual(engine.action(for: try RoutingDestination(domain: "notexample.com", port: 443)), .proxy)
    }

    func testDomainKeywordIsCaseInsensitiveAfterNormalization() throws {
        let rule = try RoutingRule(type: .domainKeyword, value: "ViDeO.", action: .reject)
        let engine = try RuleEngine(configuration: RoutingConfiguration(rules: [rule], final: .proxy))
        XCTAssertEqual(engine.action(for: try RoutingDestination(domain: "cdn.VIDEO.example.", port: 443)), .reject)
    }

    func testIPv4AndIPv6CIDRMatching() throws {
        let rules = [
            try RoutingRule(type: .ipCIDR, value: "203.0.113.42/24", action: .direct),
            try RoutingRule(type: .ipCIDR, value: "2001:db8::/32", action: .reject),
        ]
        let engine = try RuleEngine(configuration: RoutingConfiguration(rules: rules, final: .proxy))
        XCTAssertEqual(
            engine.action(for: try RoutingDestination(ipAddress: IPAddress("203.0.113.99"), port: 80)),
            .direct
        )
        XCTAssertEqual(
            engine.action(for: try RoutingDestination(ipAddress: IPAddress("2001:db8::1"), port: 80)),
            .reject
        )
        XCTAssertEqual(
            engine.action(for: try RoutingDestination(ipAddress: IPAddress("2001:db9::1"), port: 80)),
            .proxy
        )
        XCTAssertNoThrow(try IPAddress("::ffff:192.0.2.1"))
    }

    func testPortRuleAndFinalAction() throws {
        let rule = try RoutingRule(type: .port, value: "25", action: .reject)
        let engine = try RuleEngine(configuration: RoutingConfiguration(rules: [rule], final: .direct))
        XCTAssertEqual(
            engine.action(for: try RoutingDestination(ipAddress: IPAddress("192.0.2.1"), port: 25)),
            .reject
        )
        XCTAssertEqual(
            engine.action(for: try RoutingDestination(ipAddress: IPAddress("192.0.2.1"), port: 443)),
            .direct
        )
    }

    func testMixedRuleTypesStillUseFileOrder() throws {
        let rules = [
            try RoutingRule(type: .port, value: "443", action: .proxy),
            try RoutingRule(type: .domain, value: "blocked.example", action: .reject),
        ]
        let engine = try RuleEngine(configuration: RoutingConfiguration(rules: rules, final: .direct))
        let destination = try RoutingDestination(domain: "BLOCKED.EXAMPLE.", port: 443)
        XCTAssertEqual(engine.action(for: destination), .proxy)
    }

    func testConfigurationRejectsUnknownKeysAndBadValues() throws {
        let unknownKey = Data(#"{"version":1,"rules":[],"final":"DIRECT","extra":true}"#.utf8)
        XCTAssertThrowsError(try RoutingConfiguration.decode(from: unknownKey)) { error in
            XCTAssertEqual(error as? RoutingConfigurationError, .unknownKey("extra"))
        }

        let zeroPort = Data(#"{"version":1,"rules":[{"type":"port","value":"0","action":"DIRECT"}],"final":"PROXY"}"#.utf8)
        XCTAssertThrowsError(try RoutingConfiguration.decode(from: zeroPort))

        let wrongVersion = Data(#"{"version":2,"rules":[],"final":"DIRECT"}"#.utf8)
        XCTAssertThrowsError(try RoutingConfiguration.decode(from: wrongVersion))

        let nullDate = Data(#"{"version":1,"rules":[],"final":"DIRECT","generatedAt":null}"#.utf8)
        XCTAssertThrowsError(try RoutingConfiguration.decode(from: nullDate))
    }

    func testConfigurationValidatesDateValueLengthCIDRAndPort() throws {
        XCTAssertThrowsError(try RoutingConfiguration(
            generatedAt: "2026-02-30T00:00:00Z", rules: [], final: .direct
        ))
        XCTAssertThrowsError(try RoutingRule(
            type: .domainKeyword,
            value: String(repeating: "😀", count: 1_025),
            action: .proxy
        ))
        XCTAssertThrowsError(try RoutingRule(type: .ipCIDR, value: "192.0.2.1/33", action: .proxy))
        XCTAssertThrowsError(try RoutingRule(type: .ipCIDR, value: "2001:db8::/129", action: .proxy))
        XCTAssertThrowsError(try RoutingRule(type: .port, value: "65536", action: .proxy))
        XCTAssertThrowsError(try RoutingRule(type: .domain, value: ".example.com", action: .proxy))
    }

    func testDestinationRequiresHostAndNonZeroPort() throws {
        XCTAssertThrowsError(try RoutingDestination(port: 443))
        XCTAssertThrowsError(try RoutingDestination(domain: "example.com", port: 0))
        XCTAssertThrowsError(try RoutingDestination(domain: ".", port: 443))
    }

    func testIndexesPreserveEarlierFallbackRuleOrder() throws {
        let rules = [
            try RoutingRule(type: .domainKeyword, value: "blocked", action: .reject),
            try RoutingRule(type: .domain, value: "blocked.example", action: .direct),
            try RoutingRule(type: .port, value: "443", action: .proxy),
        ]
        let engine = try RuleEngine(configuration: RoutingConfiguration(rules: rules, final: .direct))
        XCTAssertEqual(
            engine.action(for: try RoutingDestination(domain: "blocked.example", port: 443)),
            .reject
        )
    }

    func testRuleCountIsBoundedForPacketTunnelUse() throws {
        let rule = try RoutingRule(type: .domain, value: "same.example", action: .direct)
        XCTAssertThrowsError(try RoutingConfiguration(
            rules: Array(repeating: rule, count: RoutingConfiguration.maximumRuleCount + 1),
            final: .proxy
        ))
    }

    func testIndexedExactLookupAtMaximumRuleCountPerformance() throws {
        let rules = try (0..<RoutingConfiguration.maximumRuleCount).map {
            try RoutingRule(type: .domain, value: "host\($0).example", action: .direct)
        }
        let engine = try RuleEngine(configuration: RoutingConfiguration(rules: rules, final: .proxy))
        let destination = try RoutingDestination(
            domain: "host\(RoutingConfiguration.maximumRuleCount - 1).example",
            port: 443
        )
        measure {
            for _ in 0..<1_000 {
                XCTAssertEqual(engine.action(for: destination), .direct)
            }
        }
    }
}
