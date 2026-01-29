// BuildCapabilities.swift - Compile-time feature detection

public enum BuildCapabilities {
    #if os(Linux)
    public static let tunSupported = true
    #elseif os(macOS)
    public static let tunSupported = false  // utun not yet implemented
    #else
    public static let tunSupported = false
    #endif
}
