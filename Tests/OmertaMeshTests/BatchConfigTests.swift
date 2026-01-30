@testable import OmertaMesh
import XCTest

final class BatchConfigTests: XCTestCase {

    func testDefaultValues() {
        let config = BatchConfig()
        XCTAssertEqual(config.maxFlushDelay, .milliseconds(1))
        XCTAssertEqual(config.maxBufferSize, 0)

        let explicit = BatchConfig.default
        XCTAssertEqual(explicit.maxFlushDelay, .milliseconds(1))
        XCTAssertEqual(explicit.maxBufferSize, 0)
    }

    func testResolveAllNil() {
        let resolved = BatchConfig.resolve(nil, nil)
        XCTAssertEqual(resolved, .default)
    }

    func testResolveSingleOverride() {
        let custom = BatchConfig(maxFlushDelay: .milliseconds(50), maxBufferSize: 1024)
        let resolved = BatchConfig.resolve(nil, custom)
        XCTAssertEqual(resolved, custom)
    }

    func testResolveChain() {
        let first = BatchConfig(maxFlushDelay: .milliseconds(10), maxBufferSize: 512)
        let second = BatchConfig(maxFlushDelay: .milliseconds(99), maxBufferSize: 2048)
        let resolved = BatchConfig.resolve(first, second)
        XCTAssertEqual(resolved, second)
    }

    func testNilInheritsParent() {
        let parent = BatchConfig(maxFlushDelay: .milliseconds(25), maxBufferSize: 768)
        let resolved = BatchConfig.resolve(parent, nil)
        XCTAssertEqual(resolved, parent)
    }

    func testCodableRoundTrip() throws {
        let original = BatchConfig(maxFlushDelay: .milliseconds(42), maxBufferSize: 256)
        let data = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(BatchConfig.self, from: data)
        XCTAssertEqual(decoded, original)
    }

    func testEquatable() {
        let a = BatchConfig(maxFlushDelay: .milliseconds(5), maxBufferSize: 100)
        let b = BatchConfig(maxFlushDelay: .milliseconds(5), maxBufferSize: 100)
        let c = BatchConfig(maxFlushDelay: .milliseconds(10), maxBufferSize: 100)
        let d = BatchConfig(maxFlushDelay: .milliseconds(5), maxBufferSize: 200)

        XCTAssertEqual(a, b)
        XCTAssertNotEqual(a, c)
        XCTAssertNotEqual(a, d)
    }
}
