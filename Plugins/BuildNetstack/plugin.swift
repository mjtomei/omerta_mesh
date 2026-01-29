import PackagePlugin
import Foundation

@main
struct BuildNetstackPlugin: BuildToolPlugin {
    func createBuildCommands(
        context: PluginContext,
        target: Target
    ) throws -> [Command] {
        let packageDir = context.package.directory
        let cnetstackDir = packageDir.appending(subpath: "Sources/CNetstack")
        let netstackDir = packageDir.appending(subpath: "Sources/OmertaTunnel/Netstack")

        // Use /bin/sh with explicit PATH and HOME so sandbox doesn't strip
        // tool access or Go module cache location
        let home = ProcessInfo.processInfo.environment["HOME"] ?? "/tmp"
        let script = """
            export PATH=/opt/homebrew/bin:/usr/local/go/bin:/usr/local/bin:/usr/bin:/bin
            export HOME="\(home)"
            make -C "\(netstackDir.string)" install
            """

        return [
            .prebuildCommand(
                displayName: "Building libnetstack from Go source",
                executable: Path("/bin/sh"),
                arguments: ["-c", script],
                outputFilesDirectory: cnetstackDir
            )
        ]
    }
}
