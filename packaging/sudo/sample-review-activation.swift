import AppKit
import Foundation

// Spawns the debug helper's fixed-fixture mode — the review frame on a private
// pipe, sharing PAM's review body — and samples its activation policy, active
// state, and on-screen window count every 50 ms for a bounded time, printing a
// line whenever any of them changes, then kills it. The frame is the synthetic,
// value-free fixture the wire probe emits; nothing is approved.
//
// This is the view the in-process `--grace-probe` cannot give: what a fresh
// process does before its window exists (the terminal lookup, the activation
// policy it starts with) and whether activation really waits for the grace.
//
// Usage: sample-review-activation <helper> [seconds] < frame
guard CommandLine.arguments.count >= 2 else {
  FileHandle.standardError.write(
    Data("usage: sample-review-activation <helper> [seconds] < frame\n".utf8))
  exit(64)
}
let helper = CommandLine.arguments[1]
let seconds = CommandLine.arguments.count > 2 ? Double(CommandLine.arguments[2]) ?? 2.5 : 2.5
let frame = FileHandle.standardInput.readDataToEndOfFile()

let process = Process()
process.executableURL = URL(fileURLWithPath: helper)
process.arguments = ["--synthetic-review-probe"]
let pipe = Pipe()
process.standardInput = pipe
process.standardOutput = FileHandle.nullDevice
process.standardError = FileHandle.nullDevice
do {
  try process.run()
} catch {
  FileHandle.standardError.write(Data("could not launch \(helper): \(error)\n".utf8))
  exit(1)
}
pipe.fileHandleForWriting.write(frame)
pipe.fileHandleForWriting.closeFile()

let pid = process.processIdentifier
let start = Date()
var last = ""
while Date().timeIntervalSince(start) < seconds {
  let app = NSRunningApplication(processIdentifier: pid)
  let policy: String
  switch app?.activationPolicy {
  case .regular?: policy = "regular"
  case .accessory?: policy = "accessory"
  case .prohibited?: policy = "prohibited"
  default: policy = "none"
  }
  let active = app?.isActive ?? false
  let windows =
    (CGWindowListCopyWindowInfo(.optionOnScreenOnly, kCGNullWindowID) as? [[String: Any]])?
    .filter { ($0[kCGWindowOwnerPID as String] as? Int32) == pid }.count ?? 0
  let line = "policy=\(policy) active=\(active) windows=\(windows)"
  if line != last {
    print(String(format: "t+%4dms  %@", Int(Date().timeIntervalSince(start) * 1000), line))
    last = line
  }
  usleep(50_000)
}
kill(pid, SIGKILL)
print("killed helper after \(Int(Date().timeIntervalSince(start) * 1000))ms")
