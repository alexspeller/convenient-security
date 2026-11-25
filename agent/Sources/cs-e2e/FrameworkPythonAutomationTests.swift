import ConvenientSecurity
import Foundation

/// Real installed framework runtimes, against synthetic agents and references.
/// The direct run proves bridge identity; the venv/restart run also proves the
/// invoked exec path and durable catalog preserve the two executable identities.
func frameworkPythonAutomationTests() async {
    var candidates = [
        "/opt/homebrew/bin/python3", "/usr/local/bin/python3",
        "/Library/Frameworks/Python.framework/Versions/Current/bin/python3",
    ]
    if let chosen = ProcessInfo.processInfo.environment["CSEC_E2E_FRAMEWORK_PYTHON"] {
        candidates.insert(chosen, at: 0)
    }
    let xcrun = Process()
    xcrun.executableURL = URL(fileURLWithPath: "/usr/bin/xcrun")
    xcrun.arguments = ["--find", "python3"]
    xcrun.environment = ["PATH": "/usr/bin:/bin"]
    let selected = Pipe()
    xcrun.standardOutput = selected
    xcrun.standardError = FileHandle.nullDevice
    if (try? xcrun.run()) != nil {
        let data = selected.fileHandleForReading.readDataToEndOfFile()
        xcrun.waitUntilExit()
        if xcrun.terminationStatus == 0 {
            candidates.append(String(decoding: data, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines))
        }
    }
    var seen: Set<String> = []
    var exercised = 0
    for path in candidates {
        guard let launcher = try? ExecutableInspection.plannedExecutable(command: path, mutableInterpreter: true),
              let consumerPath = ExecutableInspection.pythonFrameworkConsumerPath(forLauncherPath: launcher.canonicalPath),
              seen.insert(launcher.canonicalPath).inserted else { continue }
        exercised += 1
        let name = "framework-python-e2e-\(exercised)"
        do {
            let consumer = try ExecutableInspection.plannedExecutable(command: consumerPath, mutableInterpreter: true)
            check(launcher.cdHash != nil && consumer.cdHash != nil,
                  "framework Python: both installed images have a checked cdhash (\(path))")
            let script = URL(fileURLWithPath: e2eWorkingDirectory).appendingPathComponent(name + ".py")
            let source = """
            import ctypes, json, os, struct, subprocess, sys
            bridge, sock, expected_image = sys.argv[1:4]
            image = ctypes.create_string_buffer(4096)
            ctypes.CDLL('/usr/lib/libproc.dylib').proc_pidpath(os.getpid(), image, len(image))
            if os.fsdecode(image.value) != expected_image:
                sys.exit(3)
            ref = 'op://demo/api/key'
            payload = json.dumps({'version': 1, 'references': [ref], 'reason': 'Synthetic framework Python'}).encode()
            p = subprocess.run([bridge, 'bridge'], input=struct.pack('>I', len(payload)) + payload,
                               capture_output=True, env={'PATH': '/usr/bin:/bin', 'CSEC_SOCKET': sock})
            if p.returncode != 0 or len(p.stdout) < 4:
                sys.exit(4)
            (n,) = struct.unpack('>I', p.stdout[:4])
            response = json.loads(p.stdout[4:4+n])
            if (response.get('values') or {}).get(ref) != 'sk-demo-123':
                sys.exit(5)
            print('framework-python-ok', flush=True)
            """
            try Data(source.utf8).write(to: script)
            let enrolled = runCsec([
                "automation", "add", name, "--ref", "op://demo/api/key",
                "--reason", "Synthetic framework Python", "--max-runtime", "30",
                "--cwd", e2eWorkingDirectory,
                "--", path, script.path, csecURL.path, socketPath, consumer.canonicalPath,
            ], extraEnv: [:])
            let reviews = await accessReviewCapture.snapshot()
            let job = reviews.last?.automation?.job
            check(enrolled.status == 0 && job?.command.launcherExecutable == launcher
                    && job?.command.executable == consumer,
                  "framework Python: CLI enrolls both identities (\(path), status \(enrolled.status), err \(enrolled.err.debugDescription))")
            let ran = runCsec(["automation", "run", name], extraEnv: [:])
            let after = await accessReviewCapture.snapshot()
            check(ran.status == 0 && ran.out == "framework-python-ok\n" && after.count == reviews.count,
                  "framework Python: the real app bridge is served with no attended review "
                    + "(\(path), status \(ran.status), err \(ran.err.debugDescription))")
            let revoked = runCsec(["automation", "revoke", name], extraEnv: [:])
            check(revoked.status == 0, "framework Python: synthetic job is revoked (\(path))")

            if let survived = runAutomationDaemonAcrossRestart(AutomationRestartCase(
                name: name + "-venv", basePython: path, requireValidSignature: true
            )) {
                check(survived.status == 0 && survived.finished && survived.out.contains("venv-ok\n")
                        && survived.out.contains("first-ok\n") && survived.out.contains("after-ok\n")
                        && survived.out.contains("value: [redacted: op://demo/db/url]")
                        && !survived.out.contains("s3cr3t") && !survived.err.contains("s3cr3t"),
                      "framework Python: venv, two-image catalog and redaction survive a csecd restart "
                        + "(\(path), status \(survived.status), err \(survived.err.debugDescription))")
            }
        } catch {
            check(false, "framework Python end-to-end checks run for \(path) (\(error))")
        }
    }
    if exercised == 0 {
        print("skip - no Homebrew, python.org or selected Xcode framework Python installed")
    }
    if let chosen = ProcessInfo.processInfo.environment["CSEC_E2E_FRAMEWORK_PYTHON"] {
        let resolved = try? ExecutableInspection.resolve(command: chosen)
        check(resolved.map { seen.contains($0) } == true,
              "framework Python: CSEC_E2E_FRAMEWORK_PYTHON selects a supported installed framework")
    }
}
