import Foundation

public enum ProviderConfigurationError: Error, Equatable, Sendable {
    case invalidRelayHostname
    case invalidRelayPort
    case invalidRulesFilename
    case invalidDirectDNSHost
    case invalidProxyDNSHost
    case unknownKey(String)
}

/// Non-secret configuration shared by the containing app and Packet Tunnel extension.
/// Authentication tokens must remain in a credential store and are deliberately absent.
public struct ProviderConfiguration: Codable, Equatable, Sendable {
    public static let defaultDirectDNSHost = "223.5.5.5"
    public static let defaultProxyDNSHost = "1.1.1.1"

    public let relayHostname: String
    public let relayPort: UInt16
    public let rulesFilename: String
    public let directDNSHost: String
    public let proxyDNSHost: String

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case relayHostname
        case relayPort
        case rulesFilename
        case directDNSHost
        case proxyDNSHost
    }

    public init(
        relayHostname: String,
        relayPort: UInt16,
        rulesFilename: String = "rules.json",
        directDNSHost: String = ProviderConfiguration.defaultDirectDNSHost,
        proxyDNSHost: String = ProviderConfiguration.defaultProxyDNSHost
    ) throws {
        guard Self.isValidRelayHostname(relayHostname) else {
            throw ProviderConfigurationError.invalidRelayHostname
        }
        guard relayPort != 0 else {
            throw ProviderConfigurationError.invalidRelayPort
        }
        guard Self.isValidRulesFilename(rulesFilename) else {
            throw ProviderConfigurationError.invalidRulesFilename
        }
        guard Self.isIPAddressLiteral(directDNSHost) else {
            throw ProviderConfigurationError.invalidDirectDNSHost
        }
        guard Self.isIPAddressLiteral(proxyDNSHost) else {
            throw ProviderConfigurationError.invalidProxyDNSHost
        }

        self.relayHostname = relayHostname
        self.relayPort = relayPort
        self.rulesFilename = rulesFilename
        self.directDNSHost = directDNSHost
        self.proxyDNSHost = proxyDNSHost
    }

    public init(from decoder: Decoder) throws {
        let keys = try decoder.container(keyedBy: AnyCodingKey.self).allKeys
        let allowedKeys = Set(CodingKeys.allCases.map(\.rawValue))
        if let unknownKey = keys.map(\.stringValue).first(where: { !allowedKeys.contains($0) }) {
            throw ProviderConfigurationError.unknownKey(unknownKey)
        }

        let container = try decoder.container(keyedBy: CodingKeys.self)
        let directDNSHost = try container.contains(.directDNSHost)
            ? container.decode(String.self, forKey: .directDNSHost)
            : Self.defaultDirectDNSHost
        let proxyDNSHost = try container.contains(.proxyDNSHost)
            ? container.decode(String.self, forKey: .proxyDNSHost)
            : Self.defaultProxyDNSHost
        try self.init(
            relayHostname: container.decode(String.self, forKey: .relayHostname),
            relayPort: container.decode(UInt16.self, forKey: .relayPort),
            rulesFilename: container.decode(String.self, forKey: .rulesFilename),
            directDNSHost: directDNSHost,
            proxyDNSHost: proxyDNSHost
        )
    }

    private static func isIPAddressLiteral(_ text: String) -> Bool {
        (try? IPAddress(text)) != nil
    }

    private static func isValidRelayHostname(_ hostname: String) -> Bool {
        guard !hostname.isEmpty,
              hostname.utf8.count <= 253,
              hostname.unicodeScalars.allSatisfy({ $0.isASCII })
        else { return false }

        let labels = hostname.split(separator: ".", omittingEmptySubsequences: false)
        return labels.allSatisfy { label in
            guard (1...63).contains(label.utf8.count),
                  let first = label.utf8.first,
                  let last = label.utf8.last,
                  isASCIIAlphaNumeric(first),
                  isASCIIAlphaNumeric(last)
            else { return false }

            return label.utf8.allSatisfy { isASCIIAlphaNumeric($0) || $0 == 0x2D }
        }
    }

    private static func isASCIIAlphaNumeric(_ byte: UInt8) -> Bool {
        (0x30...0x39).contains(byte)
            || (0x41...0x5A).contains(byte)
            || (0x61...0x7A).contains(byte)
    }

    private static func isValidRulesFilename(_ filename: String) -> Bool {
        guard (1...255).contains(filename.utf8.count),
              filename != ".",
              filename != "..",
              !filename.contains("/"),
              !filename.contains("\\"),
              !filename.unicodeScalars.contains(where: { $0.value == 0 })
        else { return false }

        return URL(fileURLWithPath: filename).lastPathComponent == filename
    }
}
