import Foundation
import XCTest
@testable import IPadProxyCore

final class BoundedByteQueueTests: XCTestCase, @unchecked Sendable {
    func testFIFOItemsBytesAndMetrics() async throws {
        let queue = try BoundedByteQueue<Data>(
            maximumItems: 3,
            maximumBytes: 6,
            sizeOf: \Data.count
        )
        try await queue.enqueue(Data([1]))
        try await queue.enqueue(Data([2, 2]))
        try await queue.enqueue(Data([3, 3, 3]))

        let fullMetrics = await queue.metrics
        XCTAssertEqual(fullMetrics.currentItems, 3)
        XCTAssertEqual(fullMetrics.currentBytes, 6)
        XCTAssertEqual(fullMetrics.highWaterItems, 3)
        XCTAssertEqual(fullMetrics.highWaterBytes, 6)

        let first = try await queue.dequeue()
        let second = try await queue.dequeue()
        let third = try await queue.dequeue()
        XCTAssertEqual(first, Data([1]))
        XCTAssertEqual(second, Data([2, 2]))
        XCTAssertEqual(third, Data([3, 3, 3]))
        let drainedMetrics = await queue.metrics
        XCTAssertEqual(drainedMetrics.currentItems, 0)
        XCTAssertEqual(drainedMetrics.currentBytes, 0)
        XCTAssertEqual(drainedMetrics.dequeuedItems, 3)
    }

    func testItemAndByteLimitsRejectWithoutBlocking() async throws {
        let itemQueue = try BoundedByteQueue<Data>(
            maximumItems: 1,
            maximumBytes: 100,
            sizeOf: \Data.count
        )
        try await itemQueue.enqueue(Data())
        do {
            try await itemQueue.enqueue(Data())
            XCTFail("expected item rejection")
        } catch {
            XCTAssertEqual(error as? BoundedByteQueueError, .itemLimitReached)
        }

        let byteQueue = try BoundedByteQueue<Data>(
            maximumItems: 4,
            maximumBytes: 3,
            sizeOf: \Data.count
        )
        try await byteQueue.enqueue(Data([1, 2]))
        do {
            try await byteQueue.enqueue(Data([3, 4]))
            XCTFail("expected byte rejection")
        } catch {
            XCTAssertEqual(error as? BoundedByteQueueError, .byteLimitReached)
        }
        let metrics = await byteQueue.metrics
        XCTAssertEqual(metrics.rejectedItems, 1)
        XCTAssertEqual(metrics.currentBytes, 2)
    }

    func testFinishDrainsThenReturnsNilAndRejectsAdmission() async throws {
        let queue = try BoundedByteQueue<String>(
            maximumItems: 2,
            maximumBytes: 8,
            sizeOf: { $0.utf8.count }
        )
        try await queue.enqueue("one")
        try await queue.enqueue("two")
        await queue.finish()

        let first = try await queue.dequeue()
        let second = try await queue.dequeue()
        let end = try await queue.dequeue()
        XCTAssertEqual(first, "one")
        XCTAssertEqual(second, "two")
        XCTAssertNil(end)
        do {
            try await queue.enqueue("x")
            XCTFail("expected finished rejection")
        } catch {
            XCTAssertEqual(error as? BoundedByteQueueError, .finished)
        }
    }

    func testCancelDropsDataAndWakesWaitingConsumer() async throws {
        let queue = try BoundedByteQueue<Data>(
            maximumItems: 2,
            maximumBytes: 8,
            sizeOf: \Data.count
        )
        let consumer = Task { try await queue.dequeue() }
        await Task.yield()
        await queue.cancel()

        do {
            _ = try await consumer.value
            XCTFail("expected cancellation")
        } catch {
            XCTAssertEqual(error as? BoundedByteQueueError, .cancelled)
        }
        let metrics = await queue.metrics
        XCTAssertEqual(metrics.currentItems, 0)
        XCTAssertEqual(metrics.currentBytes, 0)

        do {
            _ = try await queue.dequeue()
            XCTFail("expected cancellation")
        } catch {
            XCTAssertEqual(error as? BoundedByteQueueError, .cancelled)
        }
    }

    func testTaskCancellationRemovesWaitingConsumer() async throws {
        let queue = try BoundedByteQueue<Data>(
            maximumItems: 1,
            maximumBytes: 1,
            sizeOf: \Data.count
        )
        let consumer = Task { try await queue.dequeue() }
        consumer.cancel()
        do {
            _ = try await consumer.value
            XCTFail("expected task cancellation")
        } catch {
            XCTAssertTrue(error is CancellationError)
        }

        try await queue.enqueue(Data([7]))
        let value = try await queue.dequeue()
        XCTAssertEqual(value, Data([7]))
    }

    func testWaitingConsumersAreBoundedAndCounted() async throws {
        let queue = try BoundedByteQueue<Data>(
            maximumItems: 1,
            maximumBytes: 1,
            sizeOf: \Data.count
        )
        let first = Task { try await queue.dequeue() }
        for _ in 0..<1_000 {
            if await queue.metrics.waitingConsumers == 1 { break }
            await Task.yield()
        }

        do {
            _ = try await queue.dequeue()
            XCTFail("expected waiting-consumer rejection")
        } catch {
            XCTAssertEqual(error as? BoundedByteQueueError, .waitingConsumerLimitReached)
        }
        let metrics = await queue.metrics
        XCTAssertEqual(metrics.waitingConsumers, 1)
        XCTAssertEqual(metrics.highWaterWaitingConsumers, 1)
        XCTAssertEqual(metrics.rejectedItems, 1)

        await queue.cancel()
        _ = try? await first.value
        let finalMetrics = await queue.metrics
        XCTAssertEqual(finalMetrics.waitingConsumers, 0)
    }

    func testInvalidConfigurationAndElementSizeAreRejected() async throws {
        XCTAssertThrowsError(
            try BoundedByteQueue<Data>(maximumItems: 0, maximumBytes: 1, sizeOf: \Data.count)
        )
        let queue = try BoundedByteQueue<Int>(maximumItems: 1, maximumBytes: 1, sizeOf: { _ in -1 })
        do {
            try await queue.enqueue(1)
            XCTFail("expected invalid size")
        } catch {
            XCTAssertEqual(error as? BoundedByteQueueError, .invalidElementSize)
        }
    }
}
