#if canImport(NetworkExtension)
import Combine
import Foundation
@preconcurrency import NetworkExtension
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
        case diagnosticsUnavailable
        case invalidDiagnosticsResponse
        case diagnosticsProviderError(TunnelDiagnosticsResponseError)
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

    func fetchDiagnostics(
        operation: TunnelDiagnosticsOperation = .snapshot
    ) async throws -> TunnelDiagnosticsSnapshot {
        guard let manager,
              [.connected, .reasserting].contains(Status(manager.connection.status)),
              let session = manager.connection as? NETunnelProviderSession
        else { throw ManagerError.diagnosticsUnavailable }

        let request = try TunnelDiagnosticsMessageCodec.encodeRequest(
            TunnelDiagnosticsRequest(operation: operation)
        )
        let responseData: Data = try await withCheckedThrowingContinuation { continuation in
            let once = ContinuationOnce(continuation)
            do {
                try session.sendProviderMessage(request) { data in
                    guard let data else {
                        once.resume(throwing: ManagerError.invalidDiagnosticsResponse)
                        return
                    }
                    once.resume(returning: data)
                }
            } catch {
                once.resume(throwing: ManagerError.diagnosticsUnavailable)
            }
        }
        let response: TunnelDiagnosticsResponse
        do {
            response = try TunnelDiagnosticsMessageCodec.decodeResponse(responseData)
        } catch {
            throw ManagerError.invalidDiagnosticsResponse
        }
        if let snapshot = response.snapshot { return snapshot }
        if let error = response.error { throw ManagerError.diagnosticsProviderError(error) }
        throw ManagerError.invalidDiagnosticsResponse
    }

    func resetDiagnostics() async throws -> TunnelDiagnosticsSnapshot {
        try await fetchDiagnostics(operation: .reset)
    }

    private func refreshStatus() {
        status = manager.map { Status($0.connection.status) } ?? .invalid
    }

    private func loadAllManagers() async throws -> [NETunnelProviderManager] {
        let result: TunnelManagerList = try await withCheckedThrowingContinuation { continuation in
            let once = ContinuationOnce(continuation)
            NETunnelProviderManager.loadAllFromPreferences { managers, error in
                if let error {
                    once.resume(throwing: error)
                } else {
                    once.resume(returning: TunnelManagerList(managers ?? []))
                }
            }
        }
        return result.values
    }

    private func save(_ manager: NETunnelProviderManager) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
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
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
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

private struct TunnelManagerList: @unchecked Sendable {
    let values: [NETunnelProviderManager]

    init(_ values: [NETunnelProviderManager]) {
        self.values = values
    }
}

private final class ContinuationOnce<Value: Sendable>: @unchecked Sendable {
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
