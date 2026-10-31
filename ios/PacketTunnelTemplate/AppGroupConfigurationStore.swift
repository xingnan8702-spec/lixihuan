#if os(iOS) || os(macOS)
import Foundation

public struct ProviderConfiguration: Codable, Equatable, Sendable {
    public let relayHostname: String
    public let relayPort: UInt16
    public let rulesFilename: String

    private enum CodingKeys: String, CodingKey {
        case relayHostname, relayPort, rulesFilename
    }

    public init(relayHostname: String, relayPort: UInt16, rulesFilename: String = "rules.json") throws {
        guard !relayHostname.isEmpty, relayHostname.utf8.count <= 253,
              relayPort != 0,
              !rulesFilename.isEmpty,
              rulesFilename != ".", rulesFilename != "..",
              URL(fileURLWithPath: rulesFilename).lastPathComponent == rulesFilename,
              !rulesFilename.contains("/"), !rulesFilename.contains("\\")
        else { throw AppGroupConfigurationError.invalidConfiguration }
        self.relayHostname = relayHostname
        self.relayPort = relayPort
        self.rulesFilename = rulesFilename
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        try self.init(
            relayHostname: container.decode(String.self, forKey: .relayHostname),
            relayPort: container.decode(UInt16.self, forKey: .relayPort),
            rulesFilename: container.decode(String.self, forKey: .rulesFilename)
        )
    }
}

public enum AppGroupConfigurationError: Error, Sendable {
    case containerUnavailable
    case invalidConfiguration
}

/// Stores non-secret provider configuration. Authentication tokens never belong here.
public struct AppGroupConfigurationStore: Sendable {
    public let containerURL: URL
    public let configurationURL: URL

    public init(groupIdentifier: String, filename: String = "provider.json") throws {
        guard !filename.isEmpty,
              filename != ".", filename != "..",
              URL(fileURLWithPath: filename).lastPathComponent == filename,
              !filename.contains("/"), !filename.contains("\\")
        else { throw AppGroupConfigurationError.invalidConfiguration }
        guard let container = FileManager.default.containerURL(
            forSecurityApplicationGroupIdentifier: groupIdentifier
        ) else { throw AppGroupConfigurationError.containerUnavailable }
        containerURL = container
        configurationURL = container.appendingPathComponent(filename, isDirectory: false)
    }

    public func load() throws -> ProviderConfiguration {
        try JSONDecoder().decode(ProviderConfiguration.self, from: Data(contentsOf: configurationURL))
    }

    public func save(_ configuration: ProviderConfiguration) throws {
        let data = try JSONEncoder().encode(configuration)
        try data.write(to: configurationURL, options: [.atomic, .completeFileProtection])
    }

    public func rulesURL(for configuration: ProviderConfiguration) -> URL {
        containerURL.appendingPathComponent(configuration.rulesFilename, isDirectory: false)
    }
}
#endif
