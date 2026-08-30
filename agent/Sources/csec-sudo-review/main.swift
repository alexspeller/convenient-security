import AppKit
import CSecuritySupport
import ConvenientSecurity
import Darwin
import Foundation

private let maximumFrameBytes = 9 * 1024

private func fail(_ message: String, status: Int32 = 64) -> Never {
  FileHandle.standardError.write(Data("csec-sudo-review: \(message)\n".utf8))
  exit(status)
}

private func readBoundedStandardInput() -> Data? {
  var result = Data()
  var buffer = [UInt8](repeating: 0, count: 1024)
  while true {
    let count = buffer.withUnsafeMutableBytes { bytes in
      read(STDIN_FILENO, bytes.baseAddress, bytes.count)
    }
    if count < 0, errno == EINTR { continue }
    if count < 0 { return nil }
    if count == 0 { return result }
    guard result.count + count <= maximumFrameBytes else { return nil }
    result.append(contentsOf: buffer.prefix(count))
  }
}

private func syntheticFixture() -> SudoAuthorizationReviewRequest {
  SudoAuthorizationReviewRequest(
    submittedCommand:
      "sudo /usr/bin/true --api-key \"[csec:secret-like]\" safe",
    workingDirectory: "/Users/example/project",
    terminal: "/dev/ttys001"
  )
}

private func runSelfTest() -> Never {
  let fixture = syntheticFixture()
  guard let frame = SudoAuthorizationReviewWire.encode(fixture),
    SudoAuthorizationReviewWire.decode(frame) == fixture,
    SudoAuthorizationReviewWire.decode(frame.dropLast()) == nil,
    SudoAuthorizationReviewWire.decode(Data(repeating: 0, count: 28)) == nil
  else { fail("wire self-test failed", status: 1) }
  print("sudo review wire self-test: pass")
  exit(0)
}

private func validateSyntheticFrame() -> Never {
  guard cs_fd_is_pipe_or_socket(STDIN_FILENO) == 1,
    let frame = readBoundedStandardInput(),
    SudoAuthorizationReviewWire.decode(frame) == syntheticFixture()
  else { fail("synthetic frame validation failed", status: 1) }
  print("sudo review C/Swift frame check: pass")
  exit(0)
}

private func renderSyntheticPreview(arguments: [String]) -> Never {
  guard (3...4).contains(arguments.count) else {
    fail("usage: csec-sudo-review --preview <output.png> [light|dark]")
  }
  let outputPath = arguments[2]
  if arguments.count == 4 {
    guard arguments[3] == "light" || arguments[3] == "dark" else {
      fail("preview appearance must be light or dark")
    }
    NSApplication.shared.appearance = NSAppearance(
      named: arguments[3] == "light" ? .aqua : .darkAqua)
  }
  let application = NSApplication.shared
  application.setActivationPolicy(.accessory)
  Task { @MainActor in
    guard
      let png = TrustedSudoAuthorizationReviewSession.previewPNG(
        syntheticFixture())
    else {
      fail("could not render preview", status: 1)
    }
    do {
      try png.write(to: URL(fileURLWithPath: outputPath))
    } catch {
      fail("could not write preview", status: 1)
    }
    print("sudo review preview: wrote PNG")
    exit(0)
  }
  application.run()
  exit(1)
}

if CommandLine.arguments == [CommandLine.arguments[0], "--self-test"] {
  runSelfTest()
}
if CommandLine.arguments == [CommandLine.arguments[0], "--validate-synthetic-frame"] {
  validateSyntheticFrame()
}
if CommandLine.arguments.count >= 2, CommandLine.arguments[1] == "--preview" {
  renderSyntheticPreview(arguments: CommandLine.arguments)
}
guard CommandLine.arguments.count == 1 else {
  fail("unexpected arguments")
}
guard cs_fd_is_pipe_or_socket(STDIN_FILENO) == 1 else {
  fail("stdin must be a private pipe")
}
guard let frame = readBoundedStandardInput(),
  let review = SudoAuthorizationReviewWire.decode(frame)
else {
  fail("invalid review request")
}

let application = NSApplication.shared
Task { @MainActor in
  let outcome = await TrustedSudoAuthorizationReviewSession.present(review)
  switch outcome {
  case .approved:
    exit(0)
  case .usePassword:
    exit(69)
  }
}
application.run()
exit(70)
