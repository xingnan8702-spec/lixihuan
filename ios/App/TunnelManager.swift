#if canImport(NetworkExtension)
import Combine
import Foundation
import NetworkExtension
import IPadProxyCore

@MainActor
final class TunnelManager: ObservableObject {
    enum Status: Equatable {
        case invalid
        case disconnected
        case connecting
        case connected
        case reasserting
        case disconnecting

        init(_ status: NEVPNStatus) {
            switch status {
            case .invalid: self = .invalid
            case .disconnected: self = .disconnected
            case .connecting: self = .connecting
            case .connected: self = .connected
            case .reasserting: self = .reasserting
            case .disconnecting: self = .disconnecting
            @unknown default: self = .invalid
            }
        }

        var title: String {
            switch self {
            case .invalid: return "Not installed"
            case .disconnected: return "Disconnected"
            case .connecting: return "Connecting"
            case .connected: return "Connected"
            case .reasserting: return "Reconnecting"
            case .disconnecting: return "Disconnecting"
            }
        }
    }

    enum ManagerError: Error {
        case profileUnavailable
    }

    @Published private(set) var status: Status = .invalid
    @Published private(set) var isInstalled = false

    private let providerBundleIdentifier: String
    private let appGroupIdentifier: String
    private var manager: NETunnelProviderManager?
    private var statusObserver: NSObjectProtocol?

    init(providerBundleIdentifier: String, appGroupIdentifier: String) {
        self.providerBundleIdentifier = providerBundleIdentifier
        self.appGroupIdentifier = appGroupIdentifier
        statusObserver = NotificationCenter.default.addObserver(
            forName: .NEVPNStatusDidChange,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            Task { @MainActor in self?.refreshStatus() }
        }
    }

    deinit {
        if let statusObserver {
            NotificationCenter.default.removeObserver(statusObserver)
        }
    }

    func load() async throws {
        let managers = try await loadAllManagers()
        manager = managers.first(where: { candidate in
            guard let tunnelProtocol = candidate.protocolConfiguration as? NETunnelProviderProtocol else {
                return false
            }
            return tunnelProtocol.providerBundleIdentifier == providerBundleIdentifier
        })
        isInstalled = manager != nil
        refreshStatus()
    }

    func installOrUpdate(configuration: ProviderConfiguration) async throws {
        let managers = try await loadAllManagers()
        let selectedManager = managers.first(where: { candidate in
            guard let tunnelProtocol = candidate.protocolConfiguration as? NETunnelProviderProtocol else {
                return false
            }
            return tunnelProtocol.providerBundleIdentifier == providerBundleIdentifier
        }) ?? NETunnelProviderManager()

        let tunnelProtocol = NETunnelProviderProtocol()
        tunnelProtocol.providerBundleIdentifier = providerBundleIdentifier
        tunnelProtocol.serverAddress = "\(configuration.relayHostname):\(configuration.relayPort)"
        tunnelProtocol.providerConfiguration = [
            "appGroupIdentifier": appGroupIdentifier,
        ]

        selectedManager.localizedDescription = "iPad Proxy"
        selectedManager.protocolConfiguration = tunnelProtocol
        selectedManager.isEnabled = true

        try await save(selectedManager)
        try await reload(selectedManager)
        manager = selectedManager
        isInstalled = true
        refreshStatus()
    }

    func start() throws {
        guard let manager, manager.isEnabled else {
            throw ManagerError.profileUnavailable
        }
        try manager.connection.startVPNTunnel()
        refreshStatus()
    }

    func stop() {
        manager?.connection.stopVPNTunnel()
        refreshStatus()
    }

    private func refreshStatus() {
        status = manager.map { Status($0.connection.status) } ?? .invalid
    }

    private func loadAllManagers() async throws -> [NETunnelProviderManager] {
        try await withCheckedThrowingContinuation { continuation in
            let once = ContinuationOnce(continuation)
            NETunnelProviderManager.loadAllFromPreferences { managers, error in
                if let error {
                    once.resume(throwing: error)
                } else {
                    once.resume(returning: managers ?? [])
                }
            }
        }
    }

    private func save(_ manager: NETunnelProviderManager) async throws {
        try await withCheckedThrowingContinuation { continuation in
            let once = ContinuationOnce(continuation)
            manager.saveToPreferences { error in
                if let error {
                    once.resume(throwing: error)
                } else {
                    once.resume(returning: ())
                }
            }
        }
    }

    private func reload(_ manager: NETunnelProviderManager) async throws {
        try await withCheckedThrowingContinuation { continuation in
            let once = ContinuationOnce(continuation)
            manager.loadFromPreferences { error in
                if let error {
                    once.resume(throwing: error)
                } else {
                    once.resume(returning: ())
                }
            }
        }
    }
}

private final class ContinuationOnce<Value>: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Value, Error>?

    init(_ continuation: CheckedContinuation<Value, Error>) {
        self.continuation = continuation
    }

    func resume(returning value: Value) {
        take()?.resume(returning: value)
    }

    func resume(throwing error: Error) {
        take()?.resume(throwing: error)
    }

    private func take() -> CheckedContinuation<Value, Error>? {
        lock.lock()
        let result = continuation
        continuation = nil
        lock.unlock()
        return result
    }
}
#endif
