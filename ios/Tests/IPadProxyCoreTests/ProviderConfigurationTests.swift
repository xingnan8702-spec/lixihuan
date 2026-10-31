import Foundation
import XCTest
@testable import IPadProxyCore

final class ProviderConfigurationTests: XCTestCase {
    func testRoundTripPreservesEveryFieldAndContainsNoToken() throws {
        let configuration = try ProviderConfiguration(
            relayHostname: "relay.example.com",
            relayPort: 65_535,
            rulesFilename: "imported-rules.json",
            directDNSHost: "2001:db8::53",
            proxyDNSHost: "9.9.9.9"
        )

        let data = try JSONEncoder().encode(configuration)
        let decoded = try JSONDecoder().decode(ProviderConfiguration.self, from: data)

        XCTAssertEqual(decoded, configuration)
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        XCTAssertEqual(
            Set(object.keys),
            ["relayHostname", "relayPort", "rulesFilename", "directDNSHost", "proxyDNSHost"]
        )
        XCTAssertNil(object["token"])
    }

    func testRelayHostnameAcceptsLengthAndLabelBoundaries() throws {
        XCTAssertNoThrow(try ProviderConfiguration(relayHostname: "a", relayPort: 1))
        XCTAssertNoThrow(try ProviderConfiguration(relayHostname: "localhost", relayPort: 443))
        XCTAssertNoThrow(try ProviderConfiguration(relayHostname: "127.0.0.1", relayPort: 443))

        let maximumHostname = [
            String(repeating: "a", count: 63),
            String(repeating: "b", count: 63),
            String(repeating: "c", count: 63),
            String(repeating: "d", count: 61),
        ].joined(separator: ".")
        XCTAssertEqual(maximumHostname.utf8.count, 253)
        XCTAssertNoThrow(try ProviderConfiguration(relayHostname: maximumHostname, relayPort: 443))
    }

    func testRelayHostnameRejectsEveryInvalidBoundaryForm() {
        let invalidHostnames = [
            "",
            ".example.com",
            "example.com.",
            "example..com",
            "-relay.example",
            "relay-.example",
            "relay_example.com",
            "relay example.com",
            "https://relay.example.com",
            "relay.example.com/path",
            "relay:443",
            "réseau.example",
            String(repeating: "a", count: 64) + ".example",
            String(repeating: "a", count: 254),
        ]

        for hostname in invalidHostnames {
            XCTAssertThrowsError(try ProviderConfiguration(relayHostname: hostname, relayPort: 443)) { error in
                XCTAssertEqual(error as? ProviderConfigurationError, .invalidRelayHostname)
            }
        }
    }

    func testRelayPortAcceptsMinimumAndMaximumAndRejectsZero() throws {
        XCTAssertEqual(try ProviderConfiguration(relayHostname: "relay", relayPort: 1).relayPort, 1)
        XCTAssertEqual(
            try ProviderConfiguration(relayHostname: "relay", relayPort: UInt16.max).relayPort,
            UInt16.max
        )
        XCTAssertThrowsError(try ProviderConfiguration(relayHostname: "relay", relayPort: 0)) { error in
            XCTAssertEqual(error as? ProviderConfigurationError, .invalidRelayPort)
        }
    }

    func testRulesFilenameAcceptsByteLengthBoundaries() throws {
        XCTAssertEqual(
            try ProviderConfiguration(relayHostname: "relay", relayPort: 443).rulesFilename,
            "rules.json"
        )
        XCTAssertNoThrow(
            try ProviderConfiguration(relayHostname: "relay", relayPort: 443, rulesFilename: "r")
        )
        XCTAssertNoThrow(
            try ProviderConfiguration(
                relayHostname: "relay",
                relayPort: 443,
                rulesFilename: String(repeating: "r", count: 255)
            )
        )
    }

    func testRulesFilenameRejectsTraversalSeparatorsNULAndOversize() {
        let invalidFilenames = [
            "",
            ".",
            "..",
            "rules/list.json",
            "rules\\list.json",
            "rules\0.json",
            String(repeating: "r", count: 256),
        ]

        for filename in invalidFilenames {
            XCTAssertThrowsError(
                try ProviderConfiguration(
                    relayHostname: "relay",
                    relayPort: 443,
                    rulesFilename: filename
                )
            ) { error in
                XCTAssertEqual(error as? ProviderConfigurationError, .invalidRulesFilename)
            }
        }
    }

    func testDecodeRejectsUnknownMissingAndOutOfRangeFields() throws {
        let unknown = Data(
            #"{"relayHostname":"relay","relayPort":443,"rulesFilename":"rules.json","token":"secret"}"#.utf8
        )
        XCTAssertThrowsError(try JSONDecoder().decode(ProviderConfiguration.self, from: unknown)) { error in
            XCTAssertEqual(error as? ProviderConfigurationError, .unknownKey("token"))
        }

        let missing = Data(#"{"relayHostname":"relay","relayPort":443}"#.utf8)
        XCTAssertThrowsError(try JSONDecoder().decode(ProviderConfiguration.self, from: missing))

        let zeroPort = Data(
            #"{"relayHostname":"relay","relayPort":0,"rulesFilename":"rules.json"}"#.utf8
        )
        XCTAssertThrowsError(try JSONDecoder().decode(ProviderConfiguration.self, from: zeroPort)) { error in
            XCTAssertEqual(error as? ProviderConfigurationError, .invalidRelayPort)
        }

        let oversizedPort = Data(
            #"{"relayHostname":"relay","relayPort":65536,"rulesFilename":"rules.json"}"#.utf8
        )
        XCTAssertThrowsError(try JSONDecoder().decode(ProviderConfiguration.self, from: oversizedPort))
    }

    func testDNSHostsAcceptOnlyIPv4AndIPv6Literals() throws {
        let ipv4 = try ProviderConfiguration(
            relayHostname: "relay",
            relayPort: 443,
            directDNSHost: "223.5.5.5",
            proxyDNSHost: "1.1.1.1"
        )
        XCTAssertEqual(ipv4.directDNSHost, "223.5.5.5")
        XCTAssertEqual(ipv4.proxyDNSHost, "1.1.1.1")

        XCTAssertNoThrow(try ProviderConfiguration(
            relayHostname: "relay",
            relayPort: 443,
            directDNSHost: "2001:db8::53",
            proxyDNSHost: "::1"
        ))

        for host in ["", "dns.example", "1.2.3", "256.1.1.1", "fe80::1%en0", "https://1.1.1.1"] {
            XCTAssertThrowsError(try ProviderConfiguration(
                relayHostname: "relay",
                relayPort: 443,
                directDNSHost: host
            )) {
                XCTAssertEqual($0 as? ProviderConfigurationError, .invalidDirectDNSHost)
            }
            XCTAssertThrowsError(try ProviderConfiguration(
                relayHostname: "relay",
                relayPort: 443,
                proxyDNSHost: host
            )) {
                XCTAssertEqual($0 as? ProviderConfigurationError, .invalidProxyDNSHost)
            }
        }
    }

    func testDefaultsAndLegacyJSONMigrationAreStable() throws {
        let configuration = try ProviderConfiguration(relayHostname: "relay", relayPort: 443)
        XCTAssertEqual(configuration.directDNSHost, "223.5.5.5")
        XCTAssertEqual(configuration.proxyDNSHost, "1.1.1.1")

        let legacy = Data(
            #"{"relayHostname":"relay","relayPort":443,"rulesFilename":"rules.json"}"#.utf8
        )
        let decoded = try JSONDecoder().decode(ProviderConfiguration.self, from: legacy)
        XCTAssertEqual(decoded.directDNSHost, ProviderConfiguration.defaultDirectDNSHost)
        XCTAssertEqual(decoded.proxyDNSHost, ProviderConfiguration.defaultProxyDNSHost)
    }

    func testDecodeRejectsNullAndInvalidDNSFields() throws {
        let nullDirect = Data(
            #"{"relayHostname":"relay","relayPort":443,"rulesFilename":"rules.json","directDNSHost":null,"proxyDNSHost":"1.1.1.1"}"#.utf8
        )
        XCTAssertThrowsError(try JSONDecoder().decode(ProviderConfiguration.self, from: nullDirect))

        let invalidProxy = Data(
            #"{"relayHostname":"relay","relayPort":443,"rulesFilename":"rules.json","directDNSHost":"223.5.5.5","proxyDNSHost":"dns.example"}"#.utf8
        )
        XCTAssertThrowsError(try JSONDecoder().decode(ProviderConfiguration.self, from: invalidProxy)) {
            XCTAssertEqual($0 as? ProviderConfigurationError, .invalidProxyDNSHost)
        }
    }
}
