import Foundation

public enum ManagedFlowCoordinatorError: Error, Equatable, Sendable {
    /// The target is inside a configured Fake IP pool but has no live mapping.
    /// Such a target must never be routed by its synthetic address.
    case unknownFakeIPAddress(IPAddress)
}

public struct ManagedFlowRegistrySnapshot: Equatable, Sendable {
    public let active: Int
    public let highWaterActive: Int

    public init(active: Int, highWaterActive: Int) {
        self.active = active
        self.highWaterActive = highWaterActive
    }
}

private protocol ManagedFlowRegistration: Sendable {
    func close() async
}

/// Strongly owns every registered managed flow until that flow finishes its
/// idempotent cleanup. A tunnel owner can therefore close forgotten flows by
/// calling `closeAll()` without relying on asynchronous destruction.
public actor ManagedFlowRegistry {
    private var flows: [UUID: any ManagedFlowRegistration] = [:]
    private var highWaterActive = 0

    public init() {}

    fileprivate func register(_ flow: any ManagedFlowRegistration, id: UUID) {
        flows[id] = flow
        highWaterActive = max(highWaterActive, flows.count)
    }

    fileprivate func unregister(id: UUID) {
        flows.removeValue(forKey: id)
    }

    public var snapshot: ManagedFlowRegistrySnapshot {
        ManagedFlowRegistrySnapshot(active: flows.count, highWaterActive: highWaterActive)
    }

    /// Closes the flows present when this call starts. Concurrent `closeAll()`,
    /// per-flow close, EOF, and I/O failures converge on each wrapper's single
    /// cleanup gate.
    public func closeAll() async {
        let registered = Array(flows.values)
        await withTaskGroup(of: Void.self) { group in
            for flow in registered {
                group.addTask { await flow.close() }
            }
        }
    }
}

/// Opens routed flows while transferring deterministic ownership of their
/// limiter permit and optional Fake IP lease to the returned managed wrapper.
/// Registered wrappers remain reachable by `closeAll()` even if their original
/// owner forgets to close them.
public actor ManagedFlowCoordinator {
    private let router: FlowRouter
    private let limiter: FlowLimiter
    private let fakeIPStore: FakeIPStore
    private let registry: ManagedFlowRegistry

    public init(
        router: FlowRouter,
        limiter: FlowLimiter,
        fakeIPStore: FakeIPStore,
        registry: ManagedFlowRegistry = ManagedFlowRegistry()
    ) {
        self.router = router
        self.limiter = limiter
        self.fakeIPStore = fakeIPStore
        self.registry = registry
    }

    public func openTCP(to target: Address) async throws -> ManagedTCPByteStream {
        let permit = try await limiter.beginOpening(.tcp)
        var lease: FakeIPLease?
        var openedStream: (any TCPByteStream)?

        do {
            let resolved = try await resolve(target)
            lease = resolved.lease
            let stream = try await router.routeTCP(
                destination: resolved.destination,
                target: resolved.target
            )
            openedStream = stream
            try await limiter.activate(permit)

            let registrationID = UUID()
            let managed = ManagedTCPByteStream(
                stream: stream,
                lease: lease,
                permit: permit,
                fakeIPStore: fakeIPStore,
                limiter: limiter,
                registry: registry,
                registrationID: registrationID
            )
            await registry.register(managed, id: registrationID)
            return managed
        } catch {
            if let openedStream { await openedStream.close() }
            if let lease { await fakeIPStore.release(lease) }
            _ = await limiter.release(permit)
            throw error
        }
    }

    public func openUDP(to target: Address) async throws -> ManagedUDPAssociation {
        let permit = try await limiter.beginOpening(.udp)
        var lease: FakeIPLease?
        var openedAssociation: (any UDPDatagramAssociation)?

        do {
            let resolved = try await resolve(target)
            lease = resolved.lease
            let association = try await router.routeUDP(
                destination: resolved.destination,
                target: resolved.target
            )
            openedAssociation = association
            try await limiter.activate(permit)

            let registrationID = UUID()
            let managed = ManagedUDPAssociation(
                association: association,
                lease: lease,
                permit: permit,
                fakeIPStore: fakeIPStore,
                limiter: limiter,
                registry: registry,
                registrationID: registrationID
            )
            await registry.register(managed, id: registrationID)
            return managed
        } catch {
            if let openedAssociation { await openedAssociation.close() }
            if let lease { await fakeIPStore.release(lease) }
            _ = await limiter.release(permit)
            throw error
        }
    }

    public func closeAll() async {
        await registry.closeAll()
    }

    public var snapshot: ManagedFlowRegistrySnapshot {
        get async { await registry.snapshot }
    }

    private struct ResolvedTarget: Sendable {
        let destination: RoutingDestination
        let target: Address
        let lease: FakeIPLease?
    }

    private func resolve(_ target: Address) async throws -> ResolvedTarget {
        if let domain = target.domain {
            return ResolvedTarget(
                destination: try RoutingDestination(domain: domain, port: target.port),
                target: target,
                lease: nil
            )
        }

        let family: IPAddressFamily = target.kind == .ipv4 ? .ipv4 : .ipv6
        let address = IPAddress.validated(family: family, bytes: target.ipBytes ?? [])
        switch await fakeIPStore.acquireLease(forFlow: address) {
        case .notManaged:
            return ResolvedTarget(
                destination: try RoutingDestination(ipAddress: address, port: target.port),
                target: target,
                lease: nil
            )
        case .unknownManagedAddress:
            throw ManagedFlowCoordinatorError.unknownFakeIPAddress(address)
        case let .acquired(lease):
            return ResolvedTarget(
                destination: try RoutingDestination(domain: lease.domain, port: target.port),
                target: try Address.domain(lease.domain, port: target.port),
                lease: lease
            )
        }
    }
}

/// A TCP stream that releases its Fake IP lease and flow permit after closing
/// the underlying stream. EOF and every underlying I/O error perform the same
/// cleanup automatically before the original error is rethrown.
public actor ManagedTCPByteStream: TCPByteStream, ManagedFlowRegistration {
    private let stream: any TCPByteStream
    private let lease: FakeIPLease?
    private let permit: FlowPermit
    private let fakeIPStore: FakeIPStore
    private let limiter: FlowLimiter
    private let registry: ManagedFlowRegistry
    private let registrationID: UUID
    private var isClosed = false
    private var cleanupTask: Task<Void, Never>?

    init(
        stream: any TCPByteStream,
        lease: FakeIPLease?,
        permit: FlowPermit,
        fakeIPStore: FakeIPStore,
        limiter: FlowLimiter,
        registry: ManagedFlowRegistry,
        registrationID: UUID
    ) {
        self.stream = stream
        self.lease = lease
        self.permit = permit
        self.fakeIPStore = fakeIPStore
        self.limiter = limiter
        self.registry = registry
        self.registrationID = registrationID
    }

    public func send(_ bytes: Data) async throws {
        guard !isClosed else { throw TransportError.closed }
        do {
            try await stream.send(bytes)
        } catch {
            await cleanup()
            throw error
        }
    }

    public func receive(maxBytes: Int) async throws -> Data? {
        guard !isClosed else { return nil }
        do {
            let bytes = try await stream.receive(maxBytes: maxBytes)
            if bytes == nil { await cleanup() }
            return bytes
        } catch {
            await cleanup()
            throw error
        }
    }

    /// Half-closes only the write side on success. An underlying failure is
    /// terminal and releases all flow ownership before being rethrown.
    public func finishSending() async throws {
        guard !isClosed else { throw TransportError.closed }
        do {
            try await stream.finishSending()
        } catch {
            await cleanup()
            throw error
        }
    }

    public func close() async {
        await cleanup()
    }

    private func cleanup() async {
        if let cleanupTask {
            await cleanupTask.value
            return
        }
        isClosed = true
        let stream = stream
        let lease = lease
        let fakeIPStore = fakeIPStore
        let limiter = limiter
        let permit = permit
        let registry = registry
        let registrationID = registrationID
        let task = Task {
            await stream.close()
            if let lease { await fakeIPStore.release(lease) }
            _ = await limiter.release(permit)
            await registry.unregister(id: registrationID)
        }
        cleanupTask = task
        await task.value
    }
}

/// A fixed-target UDP association with deterministic, idempotent cleanup.
public actor ManagedUDPAssociation: UDPDatagramAssociation, ManagedFlowRegistration {
    private let association: any UDPDatagramAssociation
    private let lease: FakeIPLease?
    private let permit: FlowPermit
    private let fakeIPStore: FakeIPStore
    private let limiter: FlowLimiter
    private let registry: ManagedFlowRegistry
    private let registrationID: UUID
    private var isClosed = false
    private var cleanupTask: Task<Void, Never>?

    init(
        association: any UDPDatagramAssociation,
        lease: FakeIPLease?,
        permit: FlowPermit,
        fakeIPStore: FakeIPStore,
        limiter: FlowLimiter,
        registry: ManagedFlowRegistry,
        registrationID: UUID
    ) {
        self.association = association
        self.lease = lease
        self.permit = permit
        self.fakeIPStore = fakeIPStore
        self.limiter = limiter
        self.registry = registry
        self.registrationID = registrationID
    }

    public func send(_ payload: Data) async throws {
        guard !isClosed else { throw TransportError.closed }
        do {
            try await association.send(payload)
        } catch {
            await cleanup()
            throw error
        }
    }

    public func receive() async throws -> Data? {
        guard !isClosed else { return nil }
        do {
            let payload = try await association.receive()
            if payload == nil { await cleanup() }
            return payload
        } catch {
            await cleanup()
            throw error
        }
    }

    public func close() async {
        await cleanup()
    }

    private func cleanup() async {
        if let cleanupTask {
            await cleanupTask.value
            return
        }
        isClosed = true
        let association = association
        let lease = lease
        let fakeIPStore = fakeIPStore
        let limiter = limiter
        let permit = permit
        let registry = registry
        let registrationID = registrationID
        let task = Task {
            await association.close()
            if let lease { await fakeIPStore.release(lease) }
            _ = await limiter.release(permit)
            await registry.unregister(id: registrationID)
        }
        cleanupTask = task
        await task.value
    }
}
