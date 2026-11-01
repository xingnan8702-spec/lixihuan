import Foundation

public enum DNSProxyError: Error, Equatable, Sendable {
    case truncated
    case trailingBytes
    case invalidHeader
    case invalidQuestionCount(UInt16)
    case invalidName
    case compressionLoop
    case invalidTCPFrame
    case messageTooLarge
}

public enum DNSUpstreamValidationError: Error, Equatable, Sendable {
    case malformedResponse
    case transactionIDMismatch
    case responseFlagMissing
    case opcodeMismatch
    case questionMismatch
}

public enum DNSDecision: Equatable, Sendable {
    case respond(Data)
    /// The selected action is preserved so the I/O layer cannot accidentally
    /// send a PROXY DNS query through a DIRECT resolver.
    case forward(Data, action: RoutingAction)
}

public actor DNSProxyCore {
    public static let typeA: UInt16 = 1
    public static let typeAAAA: UInt16 = 28

    private let fakeIPStore: FakeIPStore
    private let answerTTL: UInt32
    private var ruleEngine: RuleEngine

    public init(ruleEngine: RuleEngine, fakeIPStore: FakeIPStore, answerTTL: UInt32 = 300) {
        self.ruleEngine = ruleEngine
        self.fakeIPStore = fakeIPStore
        self.answerTTL = answerTTL
    }

    public func updateRuleEngine(_ engine: RuleEngine) {
        ruleEngine = engine
    }

    public func handleQuery(_ message: Data) async throws -> DNSDecision {
        let question = try DNSMessageParser.parse(message)
        let destination = try RoutingDestination(domain: question.name, port: 53)
        let action = ruleEngine.action(for: destination)

        if action == .reject {
            return .respond(try response(for: question, rcode: 5, address: nil))
        }

        guard question.type == Self.typeA || question.type == Self.typeAAAA,
              question.queryClass == 1
        else { return .forward(message, action: action) }

        switch action {
        case .direct:
            return .forward(message, action: .direct)
        case .reject:
            // Handled above. Keeping the case explicit prevents future enum changes
            // from creating an implicit forwarding path.
            return .respond(try response(for: question, rcode: 5, address: nil))
        case .proxy:
            let family: IPAddressFamily = question.type == Self.typeA ? .ipv4 : .ipv6
            let address = try await fakeIPStore.address(for: question.name, family: family)
            return .respond(try response(for: question, rcode: 0, address: address))
        }
    }

    public func handleTCPFrame(_ frame: Data) async throws -> DNSDecision {
        let query = try Self.decodeTCPFrame(frame)
        switch try await handleQuery(query) {
        case let .forward(message, action):
            return .forward(try Self.encodeTCPFrame(message), action: action)
        case let .respond(message):
            return .respond(try Self.encodeTCPFrame(message))
        }
    }

    public static func encodeTCPFrame(_ message: Data) throws -> Data {
        guard !message.isEmpty, message.count <= Int(UInt16.max) else {
            throw DNSProxyError.messageTooLarge
        }
        return Data([UInt8(message.count >> 8), UInt8(message.count & 0xff)]) + message
    }

    public static func decodeTCPFrame(_ frame: Data) throws -> Data {
        guard frame.count >= 2 else { throw DNSProxyError.invalidTCPFrame }
        let bytes = [UInt8](frame)
        let length = Int(bytes[0]) << 8 | Int(bytes[1])
        guard length > 0, frame.count == length + 2 else { throw DNSProxyError.invalidTCPFrame }
        return Data(bytes[2...])
    }

    /// Validates the DNS properties that bind an upstream response to its
    /// original query. The returned value is the response's truncation bit.
    public nonisolated static func validateUpstreamResponse(
        _ response: Data,
        for query: Data
    ) throws -> Bool {
        let expected: DNSQuestion
        let actual: DNSResponseQuestion
        do {
            expected = try DNSMessageParser.parse(query)
            actual = try DNSMessageParser.parseResponse(response)
        } catch {
            throw DNSUpstreamValidationError.malformedResponse
        }

        guard actual.id == expected.id else {
            throw DNSUpstreamValidationError.transactionIDMismatch
        }
        guard actual.isResponse else {
            throw DNSUpstreamValidationError.responseFlagMissing
        }
        guard actual.opcode == expected.opcode else {
            throw DNSUpstreamValidationError.opcodeMismatch
        }
        guard actual.name == expected.name,
              actual.type == expected.type,
              actual.queryClass == expected.queryClass
        else {
            throw DNSUpstreamValidationError.questionMismatch
        }
        return actual.isTruncated
    }

    private func response(
        for question: DNSQuestion,
        rcode: UInt16,
        address: IPAddress?
    ) throws -> Data {
        var bytes: [UInt8] = []
        append(question.id, to: &bytes)
        let flags: UInt16 = 0x8000 | (question.recursionDesired ? 0x0100 : 0) | rcode
        append(flags, to: &bytes)
        append(UInt16(1), to: &bytes)
        append(UInt16(address == nil ? 0 : 1), to: &bytes)
        append(UInt16(0), to: &bytes)
        append(UInt16(0), to: &bytes)
        bytes.append(contentsOf: try DNSMessageParser.encodeName(question.name))
        append(question.type, to: &bytes)
        append(question.queryClass, to: &bytes)

        if let address {
            bytes.append(contentsOf: [0xc0, 0x0c])
            append(question.type, to: &bytes)
            append(UInt16(1), to: &bytes)
            append(answerTTL, to: &bytes)
            append(UInt16(address.rawBytes.count), to: &bytes)
            bytes.append(contentsOf: address.rawBytes)
        }
        return Data(bytes)
    }

    private func append(_ value: UInt16, to bytes: inout [UInt8]) {
        bytes.append(UInt8(value >> 8))
        bytes.append(UInt8(value & 0xff))
    }

    private func append(_ value: UInt32, to bytes: inout [UInt8]) {
        bytes.append(UInt8((value >> 24) & 0xff))
        bytes.append(UInt8((value >> 16) & 0xff))
        bytes.append(UInt8((value >> 8) & 0xff))
        bytes.append(UInt8(value & 0xff))
    }
}

private struct DNSQuestion: Sendable {
    let id: UInt16
    let opcode: UInt16
    let recursionDesired: Bool
    let name: String
    let type: UInt16
    let queryClass: UInt16
}

private struct DNSResponseQuestion: Sendable {
    let id: UInt16
    let isResponse: Bool
    let isTruncated: Bool
    let opcode: UInt16
    let name: String
    let type: UInt16
    let queryClass: UInt16
}

private enum DNSMessageParser {
    static func parseResponse(_ data: Data) throws -> DNSResponseQuestion {
        let bytes = [UInt8](data)
        guard (12...Int(UInt16.max)).contains(bytes.count) else {
            throw DNSProxyError.truncated
        }

        let id = uint16(bytes, 0)
        let flags = uint16(bytes, 2)
        let questionCount = uint16(bytes, 4)
        guard questionCount == 1 else { throw DNSProxyError.invalidQuestionCount(questionCount) }

        var offset = 12
        let name = try decodeName(bytes, offset: &offset)
        guard offset + 4 <= bytes.count else { throw DNSProxyError.truncated }
        let type = uint16(bytes, offset)
        let queryClass = uint16(bytes, offset + 2)
        offset += 4

        let recordCount = Int(uint16(bytes, 6))
            + Int(uint16(bytes, 8))
            + Int(uint16(bytes, 10))
        for _ in 0..<recordCount {
            try skipName(bytes, offset: &offset)
            guard offset + 10 <= bytes.count else { throw DNSProxyError.truncated }
            let dataLength = Int(uint16(bytes, offset + 8))
            offset += 10
            guard offset + dataLength <= bytes.count else { throw DNSProxyError.truncated }
            offset += dataLength
        }
        guard offset == bytes.count else { throw DNSProxyError.trailingBytes }

        return DNSResponseQuestion(
            id: id,
            isResponse: flags & 0x8000 != 0,
            isTruncated: flags & 0x0200 != 0,
            opcode: (flags >> 11) & 0x0f,
            name: name,
            type: type,
            queryClass: queryClass
        )
    }

    static func parse(_ data: Data) throws -> DNSQuestion {
        let bytes = [UInt8](data)
        guard bytes.count >= 12 else { throw DNSProxyError.truncated }
        let id = uint16(bytes, 0)
        let flags = uint16(bytes, 2)
        guard flags & 0x8000 == 0, flags & 0x7800 == 0 else { throw DNSProxyError.invalidHeader }
        let questionCount = uint16(bytes, 4)
        guard questionCount == 1 else { throw DNSProxyError.invalidQuestionCount(questionCount) }
        let answerCount = uint16(bytes, 6)
        let authorityCount = uint16(bytes, 8)
        let additionalCount = uint16(bytes, 10)
        guard answerCount == 0, authorityCount == 0, additionalCount <= 1 else {
            throw DNSProxyError.invalidHeader
        }

        var offset = 12
        let name = try decodeName(bytes, offset: &offset)
        guard offset + 4 <= bytes.count else { throw DNSProxyError.truncated }
        let type = uint16(bytes, offset)
        let queryClass = uint16(bytes, offset + 2)
        offset += 4

        // Modern stub resolvers commonly attach one EDNS(0) OPT record. Accept and
        // validate it while keeping the original query unchanged for forwarding.
        // Synthetic Fake-IP responses intentionally omit OPT and remain valid DNS.
        if additionalCount == 1 {
            guard offset < bytes.count, bytes[offset] == 0 else {
                throw DNSProxyError.invalidHeader
            }
            offset += 1
            guard offset + 10 <= bytes.count, uint16(bytes, offset) == 41 else {
                throw DNSProxyError.invalidHeader
            }
            let dataLength = Int(uint16(bytes, offset + 8))
            offset += 10
            guard offset + dataLength <= bytes.count else { throw DNSProxyError.truncated }
            offset += dataLength
        }
        guard offset == bytes.count else { throw DNSProxyError.trailingBytes }
        return DNSQuestion(
            id: id,
            opcode: (flags >> 11) & 0x0f,
            recursionDesired: flags & 0x0100 != 0,
            name: name,
            type: type,
            queryClass: queryClass
        )
    }

    static func encodeName(_ name: String) throws -> [UInt8] {
        let labels = name.split(separator: ".", omittingEmptySubsequences: false)
        guard !labels.isEmpty else { throw DNSProxyError.invalidName }
        var result: [UInt8] = []
        for label in labels {
            let encoded = Array(label.utf8)
            guard (1...63).contains(encoded.count) else { throw DNSProxyError.invalidName }
            result.append(UInt8(encoded.count))
            result.append(contentsOf: encoded)
        }
        result.append(0)
        guard result.count <= 255 else { throw DNSProxyError.invalidName }
        return result
    }

    private static func skipName(_ bytes: [UInt8], offset: inout Int) throws {
        var cursor = offset
        var consumed: Int?
        var visited: Set<Int> = []
        var expandedLength = 1

        while true {
            guard cursor < bytes.count else { throw DNSProxyError.truncated }
            let length = Int(bytes[cursor])
            if length == 0 {
                if consumed == nil { consumed = cursor + 1 }
                break
            }
            if length & 0xc0 == 0xc0 {
                guard cursor + 1 < bytes.count else { throw DNSProxyError.truncated }
                let pointer = (length & 0x3f) << 8 | Int(bytes[cursor + 1])
                guard pointer >= 12, pointer < cursor, pointer < bytes.count else {
                    throw DNSProxyError.invalidName
                }
                if consumed == nil { consumed = cursor + 2 }
                guard visited.insert(pointer).inserted, visited.count <= 128 else {
                    throw DNSProxyError.compressionLoop
                }
                cursor = pointer
                continue
            }
            guard length & 0xc0 == 0,
                  (1...63).contains(length),
                  cursor + 1 + length <= bytes.count
            else { throw DNSProxyError.invalidName }
            expandedLength += length + 1
            guard expandedLength <= 255 else { throw DNSProxyError.invalidName }
            cursor += 1 + length
        }
        guard let consumed else { throw DNSProxyError.invalidName }
        offset = consumed
    }

    private static func decodeName(_ bytes: [UInt8], offset: inout Int) throws -> String {
        var labels: [String] = []
        var cursor = offset
        var consumed: Int?
        var visited: Set<Int> = []
        var expandedLength = 1

        while true {
            guard cursor < bytes.count else { throw DNSProxyError.truncated }
            let length = Int(bytes[cursor])
            if length == 0 {
                if consumed == nil { consumed = cursor + 1 }
                break
            }
            if length & 0xc0 == 0xc0 {
                guard cursor + 1 < bytes.count else { throw DNSProxyError.truncated }
                let pointer = (length & 0x3f) << 8 | Int(bytes[cursor + 1])
                // A compressed name may only point backward into the DNS message's
                // name-bearing section. Header pointers and forward/self pointers
                // are malformed and can otherwise reinterpret control bytes as labels.
                guard pointer >= 12, pointer < cursor, pointer < bytes.count else {
                    throw DNSProxyError.invalidName
                }
                if consumed == nil { consumed = cursor + 2 }
                guard visited.insert(pointer).inserted, visited.count <= 128 else {
                    throw DNSProxyError.compressionLoop
                }
                cursor = pointer
                continue
            }
            guard length & 0xc0 == 0, (1...63).contains(length), cursor + 1 + length <= bytes.count else {
                throw DNSProxyError.invalidName
            }
            let labelBytes = Array(bytes[(cursor + 1)..<(cursor + 1 + length)])
            guard let label = String(bytes: labelBytes, encoding: .utf8) else {
                throw DNSProxyError.invalidName
            }
            expandedLength += length + (labels.isEmpty ? 0 : 1)
            guard expandedLength <= 254 else { throw DNSProxyError.invalidName }
            labels.append(label)
            cursor += 1 + length
        }
        guard !labels.isEmpty, let consumed else { throw DNSProxyError.invalidName }
        offset = consumed
        return try DomainNormalizer.normalizeRuleDomain(labels.joined(separator: "."))
    }

    private static func uint16(_ bytes: [UInt8], _ offset: Int) -> UInt16 {
        UInt16(bytes[offset]) << 8 | UInt16(bytes[offset + 1])
    }
}
