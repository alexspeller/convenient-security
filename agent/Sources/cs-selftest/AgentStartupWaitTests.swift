import ConvenientSecurity
import Foundation
import CSECBuildIdentity
#if canImport(Darwin)
import Darwin
#endif

// `csec doctor`'s wait for a csecd that has not answered yet (csec-tlnj): it
// waits for one launchd still runs instead of failing after a fixed 10 s, does
// not restart one that is still starting, and still ends every wait by the
// ceiling. The pid and process age come from the real launchctl output format
// and the real kernel.

func agentStartupWaitTests() {
    let sipProblem = StartupSecurityReport.sipStartupProblem(
        developmentEndpoint: false, agentReachable: false, sipStatus: .disabled)
    check(sipProblem?.contains("SIP") == true && sipProblem?.contains("macOS Recovery") == true,
          "doctor explains why csecd cannot start with SIP disabled and where to enable it")
    for state in [SIPStatus.enabled, .unknown] {
        check(StartupSecurityReport.sipStartupProblem(
            developmentEndpoint: false, agentReachable: false, sipStatus: state) == nil,
            "doctor only diagnoses disabled SIP when confirmed")
    }
    check(StartupSecurityReport.sipStartupProblem(
        developmentEndpoint: true, agentReachable: false, sipStatus: .disabled) == nil
        && StartupSecurityReport.sipStartupProblem(
            developmentEndpoint: false, agentReachable: true, sipStatus: .disabled) == nil,
        "doctor only diagnoses a production daemon that is not answering")
    agentStartupRestartTests()
    agentStartupKeepWaitingTests()
    agentStartupLaunchctlParseTests()
    agentStartupProcessAgeTests()
    agentStartupPollTests()
}

private func agentStartupRestartTests() {
    let ceiling = AgentStartupWait.ceiling
    check(AgentStartupWait.restartNow(trustFailure: true, age: 1),
          "agent startup: a csecd that failed identity verification is restarted however young")
    check(!AgentStartupWait.restartNow(trustFailure: false, age: 11),
          "agent startup: a csecd launchd started 11 s ago is waited for, not restarted")
    check(!AgentStartupWait.restartNow(trustFailure: false, age: ceiling - 1),
          "agent startup: a csecd just under the ceiling is still waited for")
    check(AgentStartupWait.restartNow(trustFailure: false, age: ceiling),
          "agent startup: a csecd at the ceiling that does not answer is restarted")
    check(AgentStartupWait.restartNow(trustFailure: false, age: nil),
          "agent startup: with no csecd running, doctor starts one at once")
}

private func agentStartupKeepWaitingTests() {
    let settle = AgentStartupWait.settle
    let ceiling = AgentStartupWait.ceiling
    check(settle == 10 && ceiling == 120,
          "agent startup: settle stays 10 s and the hang guard 120 s")
    check(AgentStartupWait.keepWaiting(elapsed: 0, age: nil)
            && AgentStartupWait.keepWaiting(elapsed: settle - 0.1, age: nil),
          "agent startup: doctor waits the settle period even before launchd reports a pid")
    check(!AgentStartupWait.keepWaiting(elapsed: settle, age: nil),
          "agent startup: past settle with no csecd running, the wait ends")
    // The 20 Oct install: csecd's first Keychain read waited 36 s on secd.
    check(AgentStartupWait.keepWaiting(elapsed: 37, age: 37),
          "agent startup: a csecd still starting 37 s after its restart is waited for")
    check(!AgentStartupWait.keepWaiting(elapsed: 50, age: ceiling),
          "agent startup: a csecd that reached the ceiling ends the wait")
    check(!AgentStartupWait.keepWaiting(elapsed: ceiling, age: 2),
          "agent startup: launchd relaunching an exiting csecd cannot extend a wait past the ceiling")
    check(!AgentStartupWait.keepWaiting(elapsed: 11, age: ceiling + 600),
          "agent startup: a long-running csecd that stopped answering is not waited for past settle")
}

private func agentStartupLaunchctlParseTests() {
    let running = """
    gui/501/\(CSECBuildIdentity.identifier) = {
    \tactive count = 4
    \tpath = (submitted by smd.328)
    \ttype = Submitted
    \tstate = running

    \tprogram identifier = Contents/MacOS/csecd (mode: 2)
    \truns = 28
    \tpid = 86667
    \timmediate reason = inefficient

    \tresource coalition = {
    \t\tID = 1024
    \t\tstate = active
    \t\tpid = 1
    \t}
    }
    """
    check(AgentStartupWait.runningPID(launchctlPrint: running) == 86667,
          "agent startup: launchctl print yields the job's running pid, not a nested one")

    let stopped = """
    gui/501/\(CSECBuildIdentity.identifier) = {
    \tstate = not running
    \truns = 28
    \tlast exit code = 0
    \tresource coalition = {
    \t\tstate = active
    \t\tpid = 1
    \t}
    }
    """
    check(AgentStartupWait.runningPID(launchctlPrint: stopped) == nil,
          "agent startup: a job launchd does not run has no pid")

    let spawning = """
    gui/501/\(CSECBuildIdentity.identifier) = {
    \tstate = spawn scheduled
    \tpid = 4242
    }
    """
    check(AgentStartupWait.runningPID(launchctlPrint: spawning) == nil,
          "agent startup: a pid is trusted only while the job's state is running")
    check(AgentStartupWait.runningPID(launchctlPrint: "") == nil,
          "agent startup: empty launchctl output has no pid")
}

private func agentStartupProcessAgeTests() {
    let child = Process()
    child.executableURL = URL(fileURLWithPath: "/bin/sleep")
    child.arguments = ["30"]
    do {
        try child.run()
    } catch {
        check(false, "agent startup: could not start a child to measure (\(error))")
        return
    }
    let pid = child.processIdentifier
    let first = AgentStartupWait.processAge(pid: pid)
    check(first.map { $0 >= 0 && $0 < 5 } ?? false,
          "agent startup: a process started just now is seconds old")
    let later = AgentStartupWait.processAge(pid: pid, now: Date().addingTimeInterval(60))
    check(later.map { $0 >= 59 && $0 < 65 } ?? false,
          "agent startup: the age grows with the clock from the kernel's start time")
    let own = AgentStartupWait.processAge(pid: getpid())
    var olderThanChild = false
    if let own, let first { olderThanChild = own >= first }
    check(olderThanChild,
          "agent startup: the selftest itself is older than the child it started")
    child.terminate()
    child.waitUntilExit()
    check(AgentStartupWait.processAge(pid: pid) == nil,
          "agent startup: a reaped process has no age")
}

/// A probe against a fake clock: each attempt and each sleep advance it.
private final class FakeAgentProbe {
    var clock = Date(timeIntervalSince1970: 1_000_000)
    var attempts = 0
    let failures: [Error]
    let answerAfter: Int?
    let attemptCost: TimeInterval

    init(failures: [Error], answerAfter: Int? = nil, attemptCost: TimeInterval = 0) {
        self.failures = failures
        self.answerAfter = answerAfter
        self.attemptCost = attemptCost
    }

    func probe() throws -> String {
        attempts += 1
        clock += attemptCost
        if let answerAfter, attempts > answerAfter { return "capabilities" }
        throw failures[min(attempts - 1, failures.count - 1)]
    }

    func poll(age: @escaping () -> TimeInterval?) -> (result: Result<String, Error>, waited: TimeInterval) {
        AgentStartupWait.poll(
            now: { self.clock }, sleep: { self.clock += $0 }, age: age, probe: probe)
    }
}

// `csec setup` (csec-0.23): on 20 Oct an install restarted csecd and setup,
// asking once, reported it unreachable while launchd's new csecd was starting.
private func agentStartupPollTests() {
    let socket = "/tmp/csec-selftest/agent.sock"
    let waitable: [AgentClient.ClientError] = [
        .connectFailed(socket), .untrustedServer("stale build"), .transportFailed,
        .daemonUnresponsive(seconds: 5), .connectionLost("agent response unavailable"),
    ]
    check(waitable.allSatisfy(AgentStartupWait.waitingCanFix),
          "agent startup: no listener, a broken or silent connection and the previous build all may be a restart")
    let final: [AgentClient.ClientError] = [
        .connectPermissionDenied(socket), .denied("consent denied"),
        .protocolFailure(.upgradeRequired, "upgrade required"), .agentError("nonce mismatch"),
    ]
    check(!final.contains(where: AgentStartupWait.waitingCanFix),
          "agent startup: a sandbox refusal or an answer from a running csecd is not waited out")
    check(!AgentStartupWait.waitingCanFix(CocoaError(.fileNoSuchFile)),
          "agent startup: an error that is not csecd's client error is not waited out")

    let answered = FakeAgentProbe(failures: [AgentClient.ClientError.connectFailed(socket)])
    let first = answered.poll(age: { nil })
    check((try? first.result.get()) == nil && answered.attempts == 41 && first.waited >= AgentStartupWait.settle,
          "agent startup: with no csecd running, setup keeps asking through the settle period, then reports")

    let restarting = FakeAgentProbe(
        failures: [AgentClient.ClientError.connectFailed(socket)], answerAfter: 8)
    let restart = restarting.poll(age: { 1 })
    check((try? restart.result.get()) == "capabilities" && restarting.attempts == 9 && restart.waited == 2,
          "agent startup: a csecd answering 2 s after its restart is waited for and its answer returned")

    let slow = FakeAgentProbe(failures: [AgentClient.ClientError.connectFailed(socket)], answerAfter: 148)
    let slowStart = slow.clock
    let slowResult = slow.poll(age: { 1 + slow.clock.timeIntervalSince(slowStart) })
    check((try? slowResult.result.get()) == "capabilities" && slowResult.waited == 37,
          "agent startup: a csecd launchd still runs is waited for past settle (37 s Keychain start, csec-tlnj)")

    let wedged = FakeAgentProbe(
        failures: [AgentClient.ClientError.daemonUnresponsive(seconds: 5)], attemptCost: 5)
    let wedgedResult = wedged.poll(age: { 1 })
    check((try? wedgedResult.result.get()) == nil && wedgedResult.waited >= AgentStartupWait.ceiling
            && wedgedResult.waited < AgentStartupWait.ceiling + 5.25,
          "agent startup: a silent csecd launchd keeps young still ends the wait by the ceiling")

    let refused = FakeAgentProbe(failures: [AgentClient.ClientError.connectPermissionDenied(socket)])
    let refusal = refused.poll(age: { 1 })
    var namesRefusal = false
    if case let .failure(error) = refusal.result,
       case AgentClient.ClientError.connectPermissionDenied = error { namesRefusal = true }
    check(namesRefusal && refused.attempts == 1 && refusal.waited == 0,
          "agent startup: a sandbox refusal is reported at once, as itself")

    let replaced = FakeAgentProbe(failures: [
        AgentClient.ClientError.untrustedServer("stale build"),
        AgentClient.ClientError.connectFailed(socket),
    ], answerAfter: 3)
    check((try? replaced.poll(age: { nil }).result.get()) == "capabilities",
          "agent startup: the previous build exiting for an update, then the new one starting, is waited through")
}
