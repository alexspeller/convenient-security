import Foundation
import CSECRootProtocol

// Batched remediation coordinator (Decision 5). Runs the audit, collects the
// fixable findings, presents them as one deselectable checklist under a single
// Touch ID, then applies the selected changes atomically per target:
//   - `.autoPrivileged` changes go through the agent-role root helper, each
//     digest-bound to its exact change (the helper independently recomputes it);
//   - `.auto` changes (only the HA-G02 screen-lock setting) are in-process
//     user-level `defaults` writes.
// A failure on one target is recorded and the remaining targets still apply; the
// whole set is idempotent and safe to re-run.
public enum HostRemediationCoordinator {
    static func run(
        request: HostRemediationRequest,
        review: PolicyReviewProvider
    ) async -> HostRemediationSummary {
        let ctx = HostAuditService.productionContext(scanFilesystem: request.scanFilesystem)
        let report = await HostAuditEngine().run(ctx)
        var plans = await HostRemediationBuilder.plans(for: report, ctx: ctx)

        // If the caller pre-selected keys, offer only those.
        if !request.selectedKeys.isEmpty {
            let wanted = Set(request.selectedKeys)
            plans = plans.filter { wanted.contains($0.item.key) }
        }
        guard !plans.isEmpty else { return HostRemediationSummary(approved: false) }

        let outcome = await review.reviewHostRemediation(
            HostRemediationReview(items: plans.map(\.item)))
        guard case let .approved(selectedKeys) = outcome else {
            return HostRemediationSummary(approved: false)
        }
        return await applySelected(plans, selectedKeys: selectedKeys, ctx: ctx)
    }

    /// Apply the selected subset of a plan set, atomically per target. Pure over
    /// the injected context (no review), so it is unit-testable with fakes.
    public static func applySelected(
        _ plans: [HostRemediationPlan],
        selectedKeys: [String],
        ctx: HostAuditContext
    ) async -> HostRemediationSummary {
        let selected = Set(selectedKeys)
        var applied: [String] = []
        var skipped: [String] = []
        var failed: [String] = []
        for plan in plans {
            guard selected.contains(plan.item.key) else {
                skipped.append(plan.item.key)
                continue
            }
            if await apply(plan, ctx: ctx) {
                applied.append(plan.item.key)
            } else {
                failed.append(plan.item.key)
            }
        }
        return HostRemediationSummary(approved: true, applied: applied, skipped: skipped, failed: failed)
    }

    /// Apply one plan atomically-per-target. Returns true only if every change in
    /// the plan applied.
    private static func apply(_ plan: HostRemediationPlan, ctx: HostAuditContext) async -> Bool {
        var ok = true
        for change in plan.privileged {
            switch await ctx.privileged.apply(change) {
            case .applied:
                continue
            case .failed, .unavailable:
                ok = false
            }
        }
        for local in plan.local {
            if await applyLocal(local, ctx: ctx) == false { ok = false }
        }
        return ok
    }

    private static func applyLocal(_ change: HostLocalChange, ctx: HostAuditContext) async -> Bool {
        switch change {
        case .setScreenLockImmediate:
            let ask = await ctx.commands.run(HostCommand(
                executable: "/usr/bin/defaults",
                arguments: ["-currentHost", "write", "com.apple.screensaver", "askForPassword", "-int", "1"],
                label: "defaults.write.screensaver.askForPassword"))
            let delay = await ctx.commands.run(HostCommand(
                executable: "/usr/bin/defaults",
                arguments: ["-currentHost", "write", "com.apple.screensaver", "askForPasswordDelay", "-int", "0"],
                label: "defaults.write.screensaver.askForPasswordDelay"))
            return ask.succeeded && delay.succeeded
        }
    }
}
