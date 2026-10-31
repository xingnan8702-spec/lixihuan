#if canImport(SwiftUI) && canImport(NetworkExtension)
import Combine
import Foundation
import IPadProxyCore

@MainActor
final class AppViewModel: ObservableObject {
    @Published var relayHostname = ""
    @Published var relayPort = "443"
    @Published var directDNSHost = ProviderConfiguration.defaultDirectDNSHost
    @Published var proxyDNSHost = ProviderConfiguration.defaultProxyDNSHost
    @Published var tokenHex = ""

    @Published private(set) var vpnStatus: TunnelManager.Status = .invalid
    @Published private(set) var isInstalled = false
    @Published private(set) var hasSavedToken = false
    @Published private(set) var isBusy = false
    @Published private(set) var rulesStatus = "No rules imported in this session."
    @Published private(set) var errorMessage: String?

    private let configurationStore: AppGroupConfigurationStore?
    private let credentialStore: KeychainCredentialStore?
    private let ruleImportService: RuleImportService?
    private let tunnelManager: TunnelManager
    private var cancellables: Set<AnyCancellable> = []
    private var didLoad = false

    init() {
        let tunnelManager = TunnelManager(
            providerBundleIdentifier: AppIdentifiers.packetTunnelBundleIdentifier,
            appGroupIdentifier: AppIdentifiers.appGroupIdentifier
        )
        self.tunnelManager = tunnelManager
        if let keychainService = AppIdentifiers.keychainService,
           let keychainAccessGroup = AppIdentifiers.keychainAccessGroup {
            credentialStore = KeychainCredentialStore(
                service: keychainService,
                accessGroup: keychainAccessGroup
            )
        } else {
            credentialStore = nil
            errorMessage = "Keychain service or access-group configuration is missing."
        }

        if let store = try? AppGroupConfigurationStore(
            groupIdentifier: AppIdentifiers.appGroupIdentifier
        ) {
            configurationStore = store
            ruleImportService = RuleImportService(
                destinationURL: store.containerURL.appendingPathComponent(
                    AppIdentifiers.rulesFilename,
                    isDirectory: false
                )
            )
        } else {
            configurationStore = nil
            ruleImportService = nil
            errorMessage = "Shared App Group storage is unavailable. Check signing and capabilities."
        }

        tunnelManager.$status
            .sink { [weak self] status in self?.vpnStatus = status }
            .store(in: &cancellables)
        tunnelManager.$isInstalled
            .sink { [weak self] installed in self?.isInstalled = installed }
            .store(in: &cancellables)
    }

    var vpnStatusTitle: String { vpnStatus.title }

    var canSaveAndInstall: Bool {
        guard !isBusy, credentialStore != nil, configurationCandidate != nil else { return false }
        return hasSavedToken || Self.parseToken(tokenHex) != nil
    }

    var canConnect: Bool {
        !isBusy && isInstalled && vpnStatus == .disconnected
    }

    var canDisconnect: Bool {
        !isBusy && [.connecting, .connected, .reasserting].contains(vpnStatus)
    }

    var canImportRules: Bool {
        !isBusy && ruleImportService != nil
    }

    func load() {
        guard !didLoad else { return }
        performOperation(failureMessage: "Could not load the VPN configuration.") { [self] in
            if let configurationStore {
                do {
                    let configuration = try configurationStore.load()
                    relayHostname = configuration.relayHostname
                    relayPort = String(configuration.relayPort)
                    directDNSHost = configuration.directDNSHost
                    proxyDNSHost = configuration.proxyDNSHost
                } catch let error as CocoaError where error.code == .fileNoSuchFile {
                    // First launch has no provider configuration yet.
                } catch {
                    errorMessage = "The saved provider configuration is invalid or unavailable."
                }
            }

            if let credentialStore {
                do {
                    _ = try await credentialStore.loadAuthenticationToken()
                    hasSavedToken = true
                } catch CredentialStoreError.notFound {
                    hasSavedToken = false
                } catch {
                    errorMessage = "The saved authentication token could not be read."
                }
            } else {
                hasSavedToken = false
                errorMessage = "Keychain service or access-group configuration is missing."
            }

            try await tunnelManager.load()
            didLoad = true
        }
    }

    func refreshVPNProfile() {
        guard didLoad, !isBusy else { return }
        performOperation(failureMessage: "Could not refresh the VPN configuration.") { [self] in
            try await tunnelManager.load()
        }
    }

    func clearSensitiveInput() {
        tokenHex = ""
    }

    func saveAndInstall() {
        guard let configuration = configurationCandidate else {
            errorMessage = "Enter a valid relay hostname, relay port, and literal DIRECT/PROXY DNS addresses."
            return
        }
        guard let configurationStore else {
            errorMessage = "Shared App Group storage is unavailable. Check signing and capabilities."
            return
        }
        guard let credentialStore else {
            errorMessage = "Keychain service or access-group configuration is missing."
            return
        }
        guard let ruleImportService else {
            errorMessage = "Shared rules storage is unavailable."
            return
        }

        let token = tokenHex.isEmpty ? nil : Self.parseToken(tokenHex)
        guard tokenHex.isEmpty || token != nil else {
            errorMessage = "The token must contain exactly 64 hexadecimal characters."
            return
        }
        guard token != nil || hasSavedToken else {
            errorMessage = "Enter the 64-character authentication token."
            return
        }

        performOperation(failureMessage: "The VPN configuration could not be saved or installed.") { [self] in
            if try await ruleImportService.ensureDefaultRulesIfMissing() {
                rulesStatus = "Created strict default rules (all traffic uses PROXY)."
            }
            if let token {
                try await credentialStore.saveAuthenticationToken(token)
                hasSavedToken = true
                tokenHex = ""
            }
            try configurationStore.save(configuration)
            try await tunnelManager.installOrUpdate(configuration: configuration)
        }
    }

    func connect() {
        guard canConnect else { return }
        performOperation(failureMessage: "The VPN could not be started.") { [self] in
            try tunnelManager.start()
        }
    }

    func disconnect() {
        guard canDisconnect else { return }
        performOperation(failureMessage: "The VPN could not be stopped.") { [self] in
            tunnelManager.stop()
        }
    }

    func importRules(from url: URL) {
        guard let ruleImportService else {
            errorMessage = "Shared App Group storage is unavailable. Rules were not changed."
            return
        }

        performOperation(failureMessage: "The rules file was rejected. Existing rules were not changed.") { [self] in
            let result = try await ruleImportService.importRules(from: url)
            rulesStatus = "Imported \(result.ruleCount) rules (generation \(result.generation))."
        }
    }

    func reportRuleSelectionFailure() {
        errorMessage = "The selected rules file could not be opened. Existing rules were not changed."
    }

    func clearError() {
        errorMessage = nil
    }

    private var configurationCandidate: ProviderConfiguration? {
        guard let port = UInt16(relayPort) else { return nil }
        return try? ProviderConfiguration(
            relayHostname: relayHostname,
            relayPort: port,
            rulesFilename: AppIdentifiers.rulesFilename,
            directDNSHost: directDNSHost,
            proxyDNSHost: proxyDNSHost
        )
    }

    private func performOperation(
        failureMessage: String,
        operation: @escaping @MainActor () async throws -> Void
    ) {
        guard !isBusy else { return }
        isBusy = true
        errorMessage = nil
        Task { @MainActor [weak self] in
            guard let self else { return }
            defer { isBusy = false }
            do {
                try await operation()
            } catch {
                // Never surface underlying descriptions: framework and storage errors may
                // contain paths or other configuration details.
                errorMessage = failureMessage
            }
        }
    }

    private static func parseToken(_ value: String) -> AuthenticationToken? {
        let bytes = Array(value.utf8)
        guard bytes.count == AuthenticationToken.byteCount * 2 else { return nil }

        var decoded = Data(capacity: AuthenticationToken.byteCount)
        for index in stride(from: 0, to: bytes.count, by: 2) {
            guard let high = hexadecimalNibble(bytes[index]),
                  let low = hexadecimalNibble(bytes[index + 1])
            else { return nil }
            decoded.append((high << 4) | low)
        }
        return try? AuthenticationToken(decoded)
    }

    private static func hexadecimalNibble(_ byte: UInt8) -> UInt8? {
        switch byte {
        case 0x30...0x39: return byte - 0x30
        case 0x41...0x46: return byte - 0x41 + 10
        case 0x61...0x66: return byte - 0x61 + 10
        default: return nil
        }
    }
}

enum AppIdentifiers {
    static let appGroupIdentifier = "group.com.example.ipadproxy"
    static let packetTunnelBundleIdentifier = "com.example.ipadproxy.PacketTunnel"
    static var keychainService: String? {
        guard let value = Bundle.main.object(forInfoDictionaryKey: "KeychainService") as? String,
              !value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        else { return nil }
        return value
    }
    static let rulesFilename = "rules.json"

    static var keychainAccessGroup: String? {
        Bundle.main.object(forInfoDictionaryKey: "KeychainAccessGroup") as? String
    }
}
#endif
