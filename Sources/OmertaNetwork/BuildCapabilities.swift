// BuildCapabilities.swift - Compile-time feature detection

public enum BuildCapabilities {
    #if os(Linux)
    public static let tunSupported = true
    #elseif os(macOS)
    public static let tunSupported = true  // via utun (future)
    #else
    public static let tunSupported = false
    #endif
}
