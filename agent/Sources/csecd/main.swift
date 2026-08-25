@preconcurrency import AppKit
import Foundation

// This entry point must remain synchronous. Running NSApplication.run() from
// an async top-level task monopolizes the main actor for the daemon's lifetime,
// so later policy reviews cannot present their AppKit window.
let application = NSApplication.shared
application.setActivationPolicy(.accessory)
Task.detached(priority: .userInitiated) {
  await startAgentServer()
}
application.run()
