// JSONCoding.swift - Centralized JSON encoder/decoder factory

import Foundation

/// Centralized JSON encoder/decoder factory
/// Provides pre-configured, reusable instances for different use cases
public enum JSONCoding {
    /// Standard encoder for general JSON encoding
    public static let encoder = JSONEncoder()

    /// Standard decoder for general JSON decoding
    public static let decoder = JSONDecoder()

    /// Encoder with sorted keys for deterministic output (signatures, testing)
    public static let signatureEncoder: JSONEncoder = {
        let encoder = JSONEncoder()
        encoder.outputFormatting = .sortedKeys
        return encoder
    }()

    /// Encoder with pretty printing and sorted keys for storage
    public static let prettyEncoder: JSONEncoder = {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        return encoder
    }()

    /// ISO8601 encoder for timestamped data
    public static let iso8601Encoder: JSONEncoder = {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        return encoder
    }()

    /// ISO8601 decoder
    public static let iso8601Decoder: JSONDecoder = {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return decoder
    }()

    /// ISO8601 pretty encoder for storage
    public static let iso8601PrettyEncoder: JSONEncoder = {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        return encoder
    }()
}
