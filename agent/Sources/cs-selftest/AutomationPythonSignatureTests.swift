import ConvenientSecurity
import Foundation

func automationPythonSignatureTests() {
    let layouts = [
        "/opt/homebrew/Cellar/python@3.14/3.14.8/Frameworks/Python.framework/Versions/3.14",
        "/Library/Frameworks/Python.framework/Versions/3.14",
        "/Applications/Xcode.app/Contents/Developer/Library/Frameworks/Python3.framework/Versions/3.9",
    ]
    for root in layouts {
        check(ExecutableInspection.pythonFrameworkConsumerPath(forLauncherPath: root + "/bin/python3.14")
                == root + "/Resources/Python.app/Contents/MacOS/Python",
              "automation recognizes framework Python layout \(root)")
    }
    for path in [
        "/usr/bin/python3", "/opt/mise/python/bin/python3", "/tmp/Python.app/Contents/MacOS/Python",
        layouts[0] + "/bin/not-python", layouts[0] + "/bin/python3-config",
        layouts[0] + "/bin/../bin/python3", "Python.framework/Versions/3.14/bin/python3",
    ] {
        check(ExecutableInspection.pythonFrameworkConsumerPath(forLauncherPath: path) == nil,
              "automation does not infer a Python framework re-exec for \(path)")
    }

    // Homebrew omits Python.app's resource seal. Reproduce that independently
    // of the installed Python, and ensure the exception still checks code pages
    // and cannot upgrade the consumer's assurance or apply to another app.
    let fm = FileManager.default
    let root = fm.temporaryDirectory.appendingPathComponent("csec-python-sign-\(UUID().uuidString)")
        .resolvingSymlinksInPath()
    defer { try? fm.removeItem(at: root) }
    let version = root.appendingPathComponent("Python.framework/Versions/3.14")
    let app = version.appendingPathComponent("Resources/Python.app")
    let contents = app.appendingPathComponent("Contents")
    let image = contents.appendingPathComponent("MacOS/Python")
    let resource = contents.appendingPathComponent("Resources/fixture.txt")
    func run(_ executable: String, _ arguments: [String]) throws -> Bool {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        try process.run()
        process.waitUntilExit()
        return process.terminationStatus == 0
    }
    do {
        try fm.createDirectory(at: image.deletingLastPathComponent(), withIntermediateDirectories: true)
        try fm.createDirectory(at: resource.deletingLastPathComponent(), withIntermediateDirectories: true)
        let plist: [String: String] = [
            "CFBundleExecutable": "Python", "CFBundleIdentifier": "test.csec.framework-python",
            "CFBundlePackageType": "APPL", "CFBundleVersion": "1",
        ]
        try PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0)
            .write(to: contents.appendingPathComponent("Info.plist"))
        try Data("synthetic resource".utf8).write(to: resource)
        guard try run("/usr/bin/lipo", ["/bin/echo", "-thin", "arm64e", "-output", image.path]) else {
            check(false, "automation signature fixture extracts the native executable")
            return
        }
        try fm.setAttributes([.posixPermissions: 0o755], ofItemAtPath: image.path)
        guard try run("/usr/bin/codesign", ["--force", "--sign", "-", "--timestamp=none", app.path]) else {
            check(false, "automation signature fixture signs the synthetic Python.app")
            return
        }
        let sealed = try ExecutableInspection.plannedExecutable(command: image.path)
        check(sealed.cdHash != nil, "automation signature fixture starts with a valid sealed app")
        try fm.removeItem(at: resource)
        let strict = try ExecutableInspection.plannedExecutable(command: image.path)
        let mutable = try ExecutableInspection.plannedExecutable(command: image.path, mutableInterpreter: true)
        check(strict.cdHash == nil && mutable.cdHash == sealed.cdHash && mutable.cdHash != nil,
              "automation pins the framework executable even when its mutable app resources are absent")
        check(mutable.assurance == .unverified,
              "automation's mutable framework inspection never asserts protected assurance")
        let other = root.appendingPathComponent("Other.app")
        try fm.copyItem(at: app, to: other)
        let unrelated = try ExecutableInspection.plannedExecutable(
            command: other.appendingPathComponent("Contents/MacOS/Python").path, mutableInterpreter: true
        )
        check(unrelated.cdHash == nil,
              "automation's resource exception is limited to the Python framework consumer layout")
        let handle = try FileHandle(forUpdating: image)
        try handle.seek(toOffset: 4_096)
        let original = try handle.read(upToCount: 1)!
        try handle.seek(toOffset: 4_096)
        try handle.write(contentsOf: Data([original[0] ^ 0xff]))
        try handle.close()
        let corrupted = try ExecutableInspection.plannedExecutable(command: image.path, mutableInterpreter: true)
        check(corrupted.cdHash == nil,
              "automation rejects modified framework executable pages despite skipping resource validation")
    } catch {
        check(false, "automation framework signature checks run (\(error))")
    }
}
