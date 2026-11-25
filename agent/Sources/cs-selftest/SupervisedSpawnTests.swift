import CSecuritySupport
import Darwin
import Foundation

private struct SupervisedLaunch {
    let result: Int32
    let errorNumber: Int32
    let failedStep: cs_spawn_step
}

/// Launch `path` the way `csec ai` does for an agent's command, whose output
/// is piped rather than a terminal, then drain and reap it.
private func launchSupervised(_ path: String, workingDirectory: String? = nil) -> SupervisedLaunch {
    let argvPointers = [strdup(path), nil]
    let environmentPointers: [UnsafeMutablePointer<CChar>?] = [strdup("PATH=/usr/bin:/bin"), nil]
    defer {
        argvPointers.forEach { free($0) }
        environmentPointers.forEach { free($0) }
    }
    var childPID: Int32 = -1
    var ptyMaster: Int32 = -1
    var stdoutRead: Int32 = -1
    var stderrRead: Int32 = -1
    var failedStep = CS_SPAWN_STEP_SETUP
    var mutableArgv = argvPointers
    var mutableEnvironment = environmentPointers
    let result = mutableArgv.withUnsafeMutableBufferPointer { argvBuffer in
        mutableEnvironment.withUnsafeMutableBufferPointer { environmentBuffer in
            path.withCString { pathPointer -> Int32 in
                func spawn(_ directory: UnsafePointer<CChar>?) -> Int32 {
                    cs_spawn_supervised(
                        pathPointer, argvBuffer.baseAddress, environmentBuffer.baseAddress, directory,
                        0, CS_OUTPUT_PIPE, CS_OUTPUT_PIPE,
                        nil, 0, &childPID, &ptyMaster, &stdoutRead, &stderrRead, &failedStep
                    )
                }
                guard let workingDirectory else { return spawn(nil) }
                return workingDirectory.withCString { spawn($0) }
            }
        }
    }
    let errorNumber = errno
    if result == 0 {
        var buffer = [UInt8](repeating: 0, count: 256)
        for fd in [stdoutRead, stderrRead] where fd >= 0 {
            while read(fd, &buffer, buffer.count) > 0 {}
            close(fd)
        }
        var status: Int32 = 0
        while waitpid(childPID, &status, 0) < 0, errno == EINTR {}
    }
    return SupervisedLaunch(result: result, errorNumber: errorNumber, failedStep: failedStep)
}

func supervisedSpawnTests() {
    print("\n# supervised spawn: launching an agent's command")

    // On macOS 27.2 a parent setpgid(pid, pid) racing the child's own
    // setpgid(0, 0) failed about 1 launch in 400 with EPERM at setpgid, which
    // `csec ai` reported as "could not launch the child: Operation not
    // permitted". 3000 launches saw 7 such failures with the race and none
    // without it, so a reintroduced race fails this check almost surely.
    let launches = 3000
    var failures: [UInt32: (count: Int, errorNumber: Int32)] = [:]
    for _ in 0..<launches {
        let launch = launchSupervised("/usr/bin/true")
        if launch.result != 0 {
            let previous = failures[launch.failedStep.rawValue]?.count ?? 0
            failures[launch.failedStep.rawValue] = (previous + 1, launch.errorNumber)
        }
    }
    let summary = failures.map { "step \($0.key): \($0.value.count) x errno \($0.value.errorNumber)" }
    check(failures.isEmpty,
        "\(launches) piped launches all start" + (summary.isEmpty ? "" : " (\(summary.joined(separator: ", ")))"))

    let success = launchSupervised("/usr/bin/true")
    check(success.result == 0 && success.failedStep == CS_SPAWN_STEP_NONE,
        "a successful launch reports no failed step")

    let missingDirectory = launchSupervised("/usr/bin/true", workingDirectory: "/csec-fixture-missing-directory")
    check(missingDirectory.result != 0 && missingDirectory.failedStep == CS_SPAWN_STEP_CHDIR
        && missingDirectory.errorNumber == ENOENT,
        "a missing working directory fails at chdir with ENOENT")

    let missingExecutable = launchSupervised("/csec-fixture-missing-executable")
    check(missingExecutable.result != 0 && missingExecutable.failedStep == CS_SPAWN_STEP_EXEC
        && missingExecutable.errorNumber == ENOENT,
        "a missing executable fails at execve with ENOENT")
}
