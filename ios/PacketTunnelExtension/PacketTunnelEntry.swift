#if canImport(NetworkExtension) && canImport(Tun2SocksKit)
import Foundation
import IPadProxyCore
import NetworkExtension

public enum PacketTunnelEntryError: LocalizedError, Equatable, Sendable {
    case invalidProviderProtocol
    case invalidProviderConfiguration
    case appGroupUnavailable
    case invalidSavedConfiguration
    case invalidRules
    case invalidBundleConfiguration
    case credentialUnavailable
    case runtimeConstructionFailed

    public var errorDescription: String? {
        switch self {
        case .invalidProviderProtocol:
            "The VPN profile does not contain the expected tunnel protocol."
        case .invalidProviderConfiguration:
            "The VPN profile provider configuration is invalid."
        case .appGroupUnavailable:
            "Shared App Group storage is unavailable."
        case .invalidSavedConfiguration:
            "The saved provider configuration is missing or invalid."
        case .invalidRules:
            "The saved routing rules are missing or invalid."
        case .invalidBundleConfiguration:
            "The extension bundle configuration is missing or invalid."
        case .credentialUnavailable:
            "The authentication credential is missing or unavailable."
        case .runtimeConstructionFailed:
            "The tunnel runtime could not be constructed."
        }
    }
}

/// Production extension assembly for the local v0.2.5 UDP and DNS integration.
/// Every missing or malformed dependency fails closed before network settings
/// are installed or the packet stack begins reading the utun interface.
final class PacketTunnelEntry: PacketTunnelProvider {
    override func makeDependencies() async throws -> PacketTunnelDependencies {
        try Task.checkCancellation()
        guard let tunnelProtocol = protocolConfiguration as? NETunnelProviderProtocol else {
            throw PacketTunnelEntryError.invalidProviderProtocol
        }
        guard let values = tunnelProtocol.providerConfiguration,
              values.count == 1,
              let appGroupIdentifier = values["appGroupIdentifier"] as? String,
              !appGroupIdentifier.isEmpty,
              appGroupIdentifier == appGroupIdentifier.trimmingCharacters(in: .whitespacesAndNewlines)
        else {
            throw PacketTunnelEntryError.invalidProviderConfiguration
        }

        let configurationStore: AppGroupConfigurationStore
        do {
            configurationStore = try AppGroupConfigurationStore(groupIdentifier: appGroupIdentifier)
        } catch {
            throw PacketTunnelEntryError.appGroupUnavailable
        }

        let configuration: ProviderConfiguration
        do {
            configuration = try configurationStore.load()
        } catch {
            throw PacketTunnelEntryError.invalidSavedConfiguration
        }
        try Task.checkCancellation()

        let ruleStore: RuleStore
        let ruleSnapshot: RuleStoreSnapshot
        do {
            ruleStore = try RuleStore(startupURL: configurationStore.rulesURL(for: configuration))
            ruleSnapshot = try await ruleStore.snapshot()
        } catch {
            throw PacketTunnelEntryError.invalidRules
        }

        guard let keychainAccessGroup = Self.requiredBundleString("KeychainAccessGroup"),
              let keychainService = Self.requiredBundleString("KeychainService")
        else {
            throw PacketTunnelEntryError.invalidBundleConfiguration
        }
        let credentials = KeychainCredentialStore(
            service: keychainService,
            accessGroup: keychainAccessGroup
        )
        do {
            _ = try await credentials.loadAuthenticationToken()
        } catch {
            throw PacketTunnelEntryError.credentialUnavailable
        }
        try Task.checkCancellation()

        do {
            let fakeIPStore = FakeIPStore()
            let limiter = FlowLimiter()
            let directTransport = try NetworkFrameworkDirectTransport()
            let proxyTransport = try NetworkFrameworkTLSTransport(
                hostname: configuration.relayHostname,
                port: configuration.relayPort,
                credentials: credentials
            )
            let router = FlowRouter(
                engine: ruleSnapshot.engine,
                directTransport: directTransport,
                proxyTransport: proxyTransport
            )
            let coordinator = ManagedFlowCoordinator(
                router: router,
                limiter: limiter,
                fakeIPStore: fakeIPStore
            )
            let directDNSServer = try Self.dnsServerAddress(configuration.directDNSHost)
            let proxyDNSServer = try Self.dnsServerAddress(configuration.proxyDNSHost)
            let directDNSResolver = try TransportDNSUpstreamResolver(
                transport: directTransport,
                server: directDNSServer
            )
            let proxyDNSResolver = try TransportDNSUpstreamResolver(
                transport: proxyTransport,
                server: proxyDNSServer
            )
            let dnsCore = DNSProxyCore(
                ruleEngine: ruleSnapshot.engine,
                fakeIPStore: fakeIPStore
            )
            let dnsService = DNSProxyService(
                core: dnsCore,
                directResolver: directDNSResolver,
                proxyResolver: proxyDNSResolver
            )
            let udpRelay = LocalSOCKS5UDPRelay(
                coordinator: coordinator,
                dnsService: dnsService,
                fatalErrorHandler: { [weak self] error in
                    self?.cancelTunnelWithError(error)
                }
            )
            let bridge = LocalSOCKS5TCPBridge(
                coordinator: coordinator,
                dnsService: dnsService,
                udpRelay: udpRelay
            )
            let adapter = HEVPacketStackAdapter(
                bridge: bridge,
                coordinator: coordinator,
                ruleStore: ruleStore,
                fakeIPStore: fakeIPStore,
                limiter: limiter,
                directTransport: directTransport,
                proxyTransport: proxyTransport,
                credentials: credentials,
                fatalErrorHandler: { [weak self] error in
                    self?.cancelTunnelWithError(error)
                }
            )
            return PacketTunnelDependencies(
                packetStack: adapter,
                networkSettings: Self.defaultNetworkSettings(
                    remoteAddress: configuration.relayHostname,
                    installFakeDNS: true
                )
            )
        } catch let error as PacketTunnelEntryError {
            throw error
        } catch {
            throw PacketTunnelEntryError.runtimeConstructionFailed
        }
    }

    private static func dnsServerAddress(_ literal: String) throws -> Address {
        let parsed = try IPAddress(literal)
        switch parsed.family {
        case .ipv4:
            return try Address.ipv4(parsed.rawBytes, port: 53)
        case .ipv6:
            return try Address.ipv6(parsed.rawBytes, port: 53)
        }
    }

    private static func requiredBundleString(_ key: String) -> String? {
        guard let value = Bundle.main.object(forInfoDictionaryKey: key) as? String,
              !value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        else { return nil }
        return value
    }
}
#endif
