import Foundation

public enum BoundedByteQueueError: Error, Equatable, Sendable {
    case invalidConfiguration
    case invalidElementSize
    case itemLimitReached
    case byteLimitReached
    case waitingConsumerLimitReached
    case finished
    case cancelled
}

public struct BoundedByteQueueMetrics: Equatable, Sendable {
    public let currentItems: Int
    public let currentBytes: Int
    public let highWaterItems: Int
    public let highWaterBytes: Int
    public let waitingConsumers: Int
    public let highWaterWaitingConsumers: Int
    public let acceptedItems: UInt64
    public let dequeuedItems: UInt64
    public let rejectedItems: UInt64

    public init(
        currentItems: Int,
        currentBytes: Int,
        highWaterItems: Int,
        highWaterBytes: Int,
        waitingConsumers: Int,
        highWaterWaitingConsumers: Int,
        acceptedItems: UInt64,
        dequeuedItems: UInt64,
        rejectedItems: UInt64
    ) {
        self.currentItems = currentItems
        self.currentBytes = currentBytes
        self.highWaterItems = highWaterItems
        self.highWaterBytes = highWaterBytes
        self.waitingConsumers = waitingConsumers
        self.highWaterWaitingConsumers = highWaterWaitingConsumers
        self.acceptedItems = acceptedItems
        self.dequeuedItems = dequeuedItems
        self.rejectedItems = rejectedItems
    }
}

/// A bounded FIFO with non-blocking admission and cancellable async dequeue.
///
/// `enqueue` either accepts an element immediately or throws; producers are
/// never stored as an unbounded list of pending continuations. `finish` rejects
/// future enqueues, drains accepted elements, then makes `dequeue` return nil.
/// `cancel` drops buffered elements and makes current and future dequeues throw
/// `.cancelled`. Waiting consumers are also capped at `maximumItems`, so an
/// empty queue cannot retain an unbounded continuation list.
public actor BoundedByteQueue<Element: Sendable> {
    private enum State: Sendable {
        case open
        case finishing
        case cancelled
    }

    private struct BufferedElement: Sendable {
        let value: Element
        let size: Int
    }

    private struct Waiter: Sendable {
        let continuation: CheckedContinuation<Element?, any Error>
    }

    private let maximumItems: Int
    private let maximumBytes: Int
    private let sizeOf: @Sendable (Element) -> Int
    private var state: State = .open
    private var elements: [BufferedElement] = []
    private var head = 0
    private var currentBytes = 0
    private var highWaterItems = 0
    private var highWaterBytes = 0
    private var highWaterWaitingConsumers = 0
    private var acceptedItems: UInt64 = 0
    private var dequeuedItems: UInt64 = 0
    private var rejectedItems: UInt64 = 0
    private var waiterOrder: [UUID] = []
    private var waiters: [UUID: Waiter] = [:]

    public init(
        maximumItems: Int,
        maximumBytes: Int,
        sizeOf: @escaping @Sendable (Element) -> Int
    ) throws {
        guard maximumItems > 0, maximumBytes >= 0 else {
            throw BoundedByteQueueError.invalidConfiguration
        }
        self.maximumItems = maximumItems
        self.maximumBytes = maximumBytes
        self.sizeOf = sizeOf
    }

    /// Attempts immediate admission. Capacity rejection never waits.
    public func enqueue(_ element: Element) throws {
        guard state == .open else {
            recordRejection()
            throw state == .cancelled ? BoundedByteQueueError.cancelled : .finished
        }

        let size = sizeOf(element)
        guard size >= 0 else {
            recordRejection()
            throw BoundedByteQueueError.invalidElementSize
        }
        guard size <= maximumBytes else {
            recordRejection()
            throw BoundedByteQueueError.byteLimitReached
        }

        if let waiter = takeFirstWaiter() {
            increment(&acceptedItems)
            increment(&dequeuedItems)
            waiter.continuation.resume(returning: element)
            return
        }

        guard bufferedCount < maximumItems else {
            recordRejection()
            throw BoundedByteQueueError.itemLimitReached
        }
        let (nextBytes, overflow) = currentBytes.addingReportingOverflow(size)
        guard !overflow, nextBytes <= maximumBytes else {
            recordRejection()
            throw BoundedByteQueueError.byteLimitReached
        }

        elements.append(BufferedElement(value: element, size: size))
        currentBytes = nextBytes
        increment(&acceptedItems)
        highWaterItems = max(highWaterItems, bufferedCount)
        highWaterBytes = max(highWaterBytes, currentBytes)
    }

    /// Returns the next element, waits while an open queue is empty, returns
    /// nil after a finished queue drains, and throws after cancellation.
    public func dequeue() async throws -> Element? {
        if let element = popFirst() { return element }
        switch state {
        case .finishing:
            return nil
        case .cancelled:
            throw BoundedByteQueueError.cancelled
        case .open:
            guard waiters.count < maximumItems else {
                recordRejection()
                throw BoundedByteQueueError.waitingConsumerLimitReached
            }
        }

        let waiterIdentity = UUID()
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                if Task.isCancelled {
                    continuation.resume(throwing: CancellationError())
                } else {
                    waiterOrder.append(waiterIdentity)
                    waiters[waiterIdentity] = Waiter(continuation: continuation)
                    highWaterWaitingConsumers = max(highWaterWaitingConsumers, waiters.count)
                }
            }
        } onCancel: {
            Task { await self.cancelWaiter(waiterIdentity) }
        }
    }

    /// Stops admission and lets consumers drain all accepted elements.
    public func finish() {
        guard state == .open else { return }
        state = .finishing
        if bufferedCount == 0 { resumeAllWaiters(returning: nil) }
    }

    /// Drops buffered elements and wakes all consumers with `.cancelled`.
    public func cancel() {
        guard state != .cancelled else { return }
        state = .cancelled
        elements.removeAll(keepingCapacity: false)
        head = 0
        currentBytes = 0
        resumeAllWaiters(throwing: BoundedByteQueueError.cancelled)
    }

    public var metrics: BoundedByteQueueMetrics {
        BoundedByteQueueMetrics(
            currentItems: bufferedCount,
            currentBytes: currentBytes,
            highWaterItems: highWaterItems,
            highWaterBytes: highWaterBytes,
            waitingConsumers: waiters.count,
            highWaterWaitingConsumers: highWaterWaitingConsumers,
            acceptedItems: acceptedItems,
            dequeuedItems: dequeuedItems,
            rejectedItems: rejectedItems
        )
    }

    private var bufferedCount: Int { elements.count - head }

    private func popFirst() -> Element? {
        guard head < elements.count else { return nil }
        let element = elements[head]
        head += 1
        currentBytes -= element.size
        increment(&dequeuedItems)

        if head > 64, head * 2 >= elements.count {
            elements.removeFirst(head)
            head = 0
        }
        if state == .finishing, bufferedCount == 0 {
            resumeAllWaiters(returning: nil)
        }
        return element.value
    }

    private func takeFirstWaiter() -> Waiter? {
        while !waiterOrder.isEmpty {
            let identity = waiterOrder.removeFirst()
            if let waiter = waiters.removeValue(forKey: identity) { return waiter }
        }
        return nil
    }

    private func cancelWaiter(_ identity: UUID) {
        guard let waiter = waiters.removeValue(forKey: identity) else { return }
        waiter.continuation.resume(throwing: CancellationError())
        compactWaiterOrderIfNeeded()
    }

    private func resumeAllWaiters(returning element: Element?) {
        let active = waiters.values
        waiters.removeAll(keepingCapacity: false)
        waiterOrder.removeAll(keepingCapacity: false)
        for waiter in active { waiter.continuation.resume(returning: element) }
    }

    private func resumeAllWaiters(throwing error: any Error) {
        let active = waiters.values
        waiters.removeAll(keepingCapacity: false)
        waiterOrder.removeAll(keepingCapacity: false)
        for waiter in active { waiter.continuation.resume(throwing: error) }
    }

    private func compactWaiterOrderIfNeeded() {
        guard waiterOrder.count > waiters.count * 2 + 64 else { return }
        waiterOrder.removeAll { waiters[$0] == nil }
    }

    private func recordRejection() { increment(&rejectedItems) }

    private func increment(_ value: inout UInt64) {
        if value < UInt64.max { value += 1 }
    }
}
