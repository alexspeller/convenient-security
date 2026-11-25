import Foundation
import CSECRootProtocol

// Value-free inputs/outputs for the batched remediation review (Decision 5): the
// user sees every fix as a default-on, deselectable checklist row and a single
// Touch ID applies the ones still selected. No secret value, path, or command
// output ever enters these types.

/// One reversible fix offered in the review checklist. `Codable` so the value-free
/// item can ride in a `HostAuditReport` for the launcher's terminal picker.
public struct HostRemediationItem: Codable, Sendable, Equatable {
    /// The catalog id / remediation key, e.g. "HA-C01".
    public let key: String
    /// Value-free one-line title (what will change).
    public let title: String
    /// Value-free detail (why it is safe / reversible).
    public let detail: String
    /// True when applying needs the root helper (shown in the row).
    public let requiresRoot: Bool

    public init(key: String, title: String, detail: String, requiresRoot: Bool) {
        self.key = key
        self.title = title
        self.detail = detail
        self.requiresRoot = requiresRoot
    }
}

public struct HostRemediationReview: Sendable {
    public let items: [HostRemediationItem]
    /// The launcher whose terminal picker selected these fixes. The panel
    /// names its tab (`caller.terminal`) and closes if it goes away.
    public let caller: CallerInfo
    public init(items: [HostRemediationItem], caller: CallerInfo) {
        self.items = items
        self.caller = caller
    }

    /// What the touch applies, as csecd's settings panel lists it: each fix
    /// by its value-free title. The terminal picker already showed the
    /// itemized, deselectable list with each fix's detail.
    public var change: SettingsChangeReviewDetails {
        SettingsChangeReviewDetails(
            title: items.count == 1 ? "Apply a Security Fix" : "Apply \(items.count) Security Fixes",
            changes: items.map(\.title),
            footnote: "Touch ID applies exactly these reversible fixes to this Mac's settings. No secret is released."
        )
    }
}

public enum HostRemediationOutcome: Sendable, Equatable {
    case denied
    /// Touch ID succeeded; apply exactly these (still-selected) keys.
    case approved(selectedKeys: [String])
}

/// A reversible in-process (unprivileged) change — the small set of fixes that
/// write user-level settings rather than going through the root helper (HA-G02's
/// defaults, HA-F13's package-manager config files).
public enum HostLocalChange: Sendable, Equatable {
    case setScreenLockImmediate
    case setReleaseCooldown(ReleaseCooldowns.Fix)
}
