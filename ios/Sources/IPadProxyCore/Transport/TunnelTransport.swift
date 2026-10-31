import Foundation

public enum TransportError: Error, Equatable, Sendable {
    case closed
    case invalidReceiveLimit
    case rejected
}

/// A cancellable, backpressured TCP byte stream.
///
/// `send` returning means the implementation accepted responsibility for all bytes;
/// callers must not treat an earlier enqueue as a successful send. Cancellation must
/// unblock pending operations. `finishSending` performs a write-side half-close while
/// leaving reads available. `close` terminates both directions and is idempotent.
public protocol TCPByteStream: Sendable {
    func send(_ bytes: Data) async throws
    func receive(maxBytes: Int) async throws -> Data?
    func finishSending() async throws
    func close() async
}

/// A cancellable UDP association that preserves datagram boundaries.
///
/// `send` is backpressured with the same completion contract as TCP. `receive` returns
/// nil after a graceful close. Production implementations must use bounded buffering.
public protocol UDPDatagramAssociation: Sendable {
    /// Sends one payload to the fixed target selected when this association opened.
    func send(_ payload: Data) async throws
    /// Receives one payload from that same target, preserving datagram boundaries.
    func receive() async throws -> Data?
    func close() async
}

/// Opens independent TCP streams and fixed-target UDP associations. Implementations
/// must propagate task cancellation to their underlying network operations.
public protocol TunnelTransport: Sendable {
    func openTCP(to target: Address) async throws -> any TCPByteStream
    func openUDP(to target: Address) async throws -> any UDPDatagramAssociation
}
