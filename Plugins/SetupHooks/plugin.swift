import PackagePlugin
import Foundation

@main
struct SetupHooks: CommandPlugin {
    func performCommand(context: PluginContext, arguments: [String]) throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/git")
        process.arguments = ["config", "core.hooksPath", ".githooks"]
        process.currentDirectoryURL = URL(fileURLWithPath: context.package.directory.string)
        try process.run()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else {
            Diagnostics.error("Failed to configure git hooks (exit \(process.terminationStatus))")
            return
        }
        print("Git hooks path set to .githooks")
    }
}
