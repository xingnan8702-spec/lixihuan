#if os(iOS) || os(macOS)
import Foundation
import IPadProxyCore

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
