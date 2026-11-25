import ConvenientSecurity
import Foundation
#if canImport(AppKit)
  import AppKit
#endif

/// The views of one panel that scroll only past the screen share what it
/// leaves (`ReviewDisclosureFit.heights`, csec-lz39).
func screenFitRuleTests() {
    let minimum = ReviewDisclosureFit.minimumHeight
    check(ReviewDisclosureFit.heights(contentHeights: [320, 200], otherHeight: 400, visibleHeight: 1_000) == [320, 200],
          "screen fit: views that fit the screen together are shown whole")
    check(ReviewDisclosureFit.heights(contentHeights: [320], otherHeight: 708, visibleHeight: 900) == [192],
          "screen fit: one view past the screen scrolls in exactly the height left")
    check(ReviewDisclosureFit.heights(contentHeights: [100, 900], otherHeight: 400, visibleHeight: 900) == [100, 400],
          "screen fit: a short view keeps its whole height and the tall one takes the rest")
    check(ReviewDisclosureFit.heights(contentHeights: [700, 900], otherHeight: 400, visibleHeight: 900) == [250, 250],
          "screen fit: two tall views are cut to the same height")
    check(ReviewDisclosureFit.heights(contentHeights: [700, 40, 900], otherHeight: 400, visibleHeight: 900) == [230, 40, 230],
          "screen fit: the cut never takes from a view that already fits its share")
    check(ReviewDisclosureFit.heights(contentHeights: [320, 400], otherHeight: 880, visibleHeight: 900) == [minimum, minimum],
          "screen fit: a panel already near the screen's height still gives each view the minimum")
    check(ReviewDisclosureFit.heights(contentHeights: [40, 400], otherHeight: 880, visibleHeight: 900) == [40, minimum],
          "screen fit: never taller than its content")
    check(ReviewDisclosureFit.heights(contentHeights: [320, 900], otherHeight: 700, visibleHeight: nil) == [320, 900],
          "screen fit: with no screen to fit, all of it shows")
    check(ReviewDisclosureFit.heights(contentHeights: [], otherHeight: 700, visibleHeight: 900) == [],
          "screen fit: a panel with no such views changes nothing")
}

#if canImport(AppKit) && canImport(LocalAuthenticationEmbeddedUI)
  /// A list of secrets or restored approvals, and the SSH request's details,
  /// are shown whole on a screen with room and otherwise fill only the screen
  /// with an always-drawn scroller beside them, not over them, and a cue under
  /// them (csec-lz39, where the release list sat in a 220-point peephole, the
  /// automation card in 340 and restore rows in 300, behind scrollers that
  /// showed only while scrolling).
  @MainActor
  func listFitPanelTests() {
      NSApplication.shared.setActivationPolicy(.accessory)
      func all(_ view: NSView) -> [NSView] { [view] + view.subviews.flatMap(all) }
      func lists(_ panel: ApprovalPanelInspection) -> [NSScrollView] {
          all(panel.window.contentView ?? NSView()).compactMap { $0 as? NSScrollView }
              .filter { $0.identifier == ReviewFittedList.scrollIdentifier && !$0.isHiddenOrHasHiddenAncestor }
      }
      func button(_ title: String, in panel: ApprovalPanelInspection) -> NSButton? {
          all(panel.window.contentView ?? NSView()).compactMap { $0 as? NSButton }.first { $0.title == title }
      }
      let visibleHeight = NSScreen.main?.visibleFrame.height

      /// Checks every shown list of `panel`, `count` of them; with `mustScroll`
      /// set, whether at least one of them scrolls.
      func checkFitted(_ name: String, _ panel: ApprovalPanelInspection, count: Int, mustScroll: Bool? = nil) {
          panel.window.contentView?.layoutSubtreeIfNeeded()
          let shownLists = lists(panel)
          check(shownLists.count == count, "\(name): shows \(count) fitted list(s) (\(shownLists.count))")
          var anyScrolls = false
          for (index, scroll) in shownLists.enumerated() {
              let label = "\(name), list \(index + 1)"
              guard let document = scroll.documentView,
                  let cue = scroll.superview?.subviews.compactMap({ $0 as? NSTextField })
                      .first(where: { $0.identifier == ReviewFittedList.overflowCueIdentifier })
              else {
                  check(false, "\(label): has a document and an overflow cue beside it")
                  continue
              }
              let clip = scroll.contentView
              let content = document.frame.height
              let shown = clip.bounds.height
              let scrolls = content > shown + 1
              anyScrolls = anyScrolls || scrolls
              check(scrolls == !cue.isHidden,
                    "\(label): the cue shows exactly when the list scrolls (content \(content), shown \(shown))")
              if scrolls {
                  check(shown >= ReviewDisclosureFit.minimumHeight - 1,
                        "\(label): a scrolling list keeps at least the minimum height (\(shown))")
                  check(scroll.scrollerStyle == .legacy && !scroll.autohidesScrollers && scroll.hasVerticalScroller,
                        "\(label): a scrolling list's scroller is always drawn")
                  check(document.frame.width <= clip.bounds.width + 0.5,
                        "\(label): the scroller sits beside the list, not over its right edge (\(document.frame.width) in \(clip.bounds.width))")
                  check(clip.bounds.minY < 0.5, "\(label): the list starts at its top")
                  // What the list draws starts at the top of what scrolls,
                  // with nothing blank above its first row.
                  if let content = document.subviews.first, let first = all(content).dropFirst()
                      .filter({ !$0.isHidden && $0.frame.height > 0 })
                      .map({ document.convert($0.bounds, from: $0).minY }).min()
                  {
                      check(first < 30,
                            "\(label): its first row is at the top of the list (\(first) points down, content frame \(content.frame))")
                  }
                  // It scrolls all the way: the last of it can be brought into view.
                  clip.scroll(to: NSPoint(x: 0, y: content - shown))
                  scroll.reflectScrolledClipView(clip)
                  check(abs(clip.bounds.maxY - content) < 1,
                        "\(label): scrolling reaches the end of the list (\(clip.bounds.maxY) of \(content))")
                  clip.scroll(to: .zero)
                  scroll.reflectScrolledClipView(clip)
              } else {
                  check(content <= shown + 1, "\(label): nothing of the list is clipped")
                  check(!scroll.hasVerticalScroller, "\(label): a list with room draws no scroller")
              }
          }
          if let mustScroll {
              check(anyScrolls == mustScroll, "\(name): \(mustScroll ? "scrolls" : "shows whole") on this screen")
          }
          if let visibleHeight {
              if anyScrolls {
                  check(panel.window.frame.height <= visibleHeight + 1,
                        "\(name): the panel grows only to the screen (\(panel.window.frame.height) vs \(visibleHeight))")
                  check(panel.window.frame.height >= visibleHeight - 1,
                        "\(name): a scrolling list uses all the height the screen leaves")
              }
          }
      }

      let caller = CallerInfo(pid: 51, startTime: 9, description: "cs-selftest fixture (pid 51)")
      let plan = DeliveryPlan(
          mechanism: .directHeap,
          executable: PlannedExecutable(canonicalPath: "/usr/bin/ruby", assurance: .independentlyProtected),
          descendantScope: .subtree, destination: .localDevelopment,
          requestedTTLSeconds: nil, operationContext: "run migrations"
      )
      /// `count` secrets, each in a store of its own, so each takes lines of
      /// its own in the tree.
      func references(_ count: Int) -> [String] {
          (1...count).map { String(format: "csec://store-%03d/API_TOKEN_%03d", $0, $0) }
      }
      func credentials(_ count: Int) -> [PolicyReviewCredential] {
          [PolicyReviewCredential(references: references(count).map { try! SecretRef($0) })]
      }
      func release(_ count: Int, command: String = "bin/rails db:migrate", restore: RestoreReviewDetails? = nil)
          -> ApprovalPanelInspection
      {
          .access(AccessPolicyReview(
              caller: caller, reason: "run migrations", plan: plan, commandLine: command,
              credentials: credentials(count),
              durationChoices: GrantDurationChoices.offered(requestedTTLSeconds: nil), restore: restore
          ))
      }
      func restore(_ count: Int) -> RestoreReviewDetails {
          RestoreReviewDetails(
              cause: .restart,
              rows: (1...count).map {
                  RestoreReviewRow(kind: .secretGrant, title: "fish \($0)", detail: "This terminal session · pid \($0)",
                                   references: ["csec://dev/API_TOKEN_\($0)"])
              },
              storeCount: 1
          )
      }

      checkFitted("release panel, three secrets", release(3), count: 1, mustScroll: false)
      // Taller than the old 220-point box, short enough for any screen the
      // panel runs on.
      let medium = release(20)
      checkFitted("release panel, 20 secrets", medium, count: 1)
      if let scroll = lists(medium).first, let visibleHeight,
          let document = scroll.documentView, document.frame.height > 220
      {
          let room = visibleHeight - (medium.window.frame.height - scroll.frame.height)
          if room > document.frame.height {
              check(scroll.frame.height >= document.frame.height - 1,
                    "release panel, 20 secrets: shown whole, not capped at the old 220 points")
          }
      } else {
          let height = lists(medium).first?.documentView?.frame.height ?? 0
          check(false, "release panel, 20 secrets: the fixture's list is taller than the old 220-point box (\(height))")
      }
      withExtendedLifetime(medium) {}
      checkFitted("release panel, 200 secrets", release(200), count: 1, mustScroll: true)

      // A long list and an opened long command share the screen: the list's
      // whole height must not push the panel's buttons off it.
      let longCommand = "bin/rails runner " + Array(repeating: "Migration.run", count: 900).joined(separator: " ")
      let both = release(200, command: longCommand)
      if let show = button("Show full command", in: both) {
          show.performClick(nil)
          checkFitted("release panel, 200 secrets and the full command", both, count: 1, mustScroll: true)
          if let visibleHeight {
              check(both.window.frame.height <= visibleHeight + 1,
                    "release panel, 200 secrets and the full command: the panel stays within the screen")
          }
          let commandCue = all(both.window.contentView ?? NSView()).compactMap { $0 as? NSTextField }
              .first { $0.identifier == ReviewCommandText.overflowCueIdentifier }
          check(commandCue?.isHidden == false, "release panel, 200 secrets and the full command: the command scrolls too")
          button("Hide full command", in: both)?.performClick(nil)
          check(commandCue?.isHidden == true,
                "release panel, 200 secrets: hiding the command hides its cue")
          checkFitted("release panel, 200 secrets, command hidden again", both, count: 1, mustScroll: true)
      } else {
          check(false, "release panel, 200 secrets and a long command: has a Show full command disclosure")
      }
      withExtendedLifetime(both) {}

      // An automation job's secrets.
      let job = AutomationJob(
          id: UUID().uuidString.lowercased(), revision: UUID().uuidString.lowercased(),
          name: "backup", reason: "nightly backup", references: references(200),
          command: AutomationCommand(
              executable: PlannedExecutable(canonicalPath: "/usr/bin/true", assurance: .unverified),
              commandLine: ["/usr/bin/true"], workingDirectory: "/tmp", commandDigest: String(repeating: "0", count: 64)
          ),
          minimumIntervalSeconds: 60, maximumRuntimeSeconds: 60, consumerTrust: .mutableInterpreted,
          createdAt: Date(), updatedAt: Date()
      )
      let automation = ApprovalPanelInspection.access(AccessPolicyReview(
          caller: caller, reason: job.reason, plan: plan, credentials: credentials(200),
          automation: AutomationReviewDetails(job: job)))
      checkFitted("automation panel, 200 secrets", automation, count: 1, mustScroll: true)
      withExtendedLifetime(automation) {}

      // What a restore reopens, alone and beside a release.
      checkFitted("restore-only panel, two rows",
                  .access(.restoreOnly(caller: caller, restore: restore(2))), count: 1, mustScroll: false)
      checkFitted("restore-only panel, 80 rows",
                  .access(.restoreOnly(caller: caller, restore: restore(80))), count: 1, mustScroll: true)
      let mixed = release(200, restore: restore(80))
      checkFitted("release panel, 200 secrets and 80 restore rows", mixed, count: 2, mustScroll: true)
      let mixedHeights = lists(mixed).map(\.frame.height)
      if mixedHeights.count == 2 {
          check(abs(mixedHeights[0] - mixedHeights[1]) < 1,
                "release panel with restore rows: two long lists share the screen equally (\(mixedHeights))")
      }
      withExtendedLifetime(mixed) {}

      // The SSH request's details, a disclosure with a key card of 200 keys.
      let ssh = SSHAccessReviewDetails(
          hostNames: ["production.example.com", "staging.example.com", "third.example.com"],
          remoteUser: "deploy", keyLabel: "work", keyAlgorithm: "ssh-ed25519")
      let sshPanel = ApprovalPanelInspection.access(AccessPolicyReview(
          caller: caller, reason: ssh.reason,
          plan: DeliveryPlan(
              mechanism: .credentialProtocol,
              executable: PlannedExecutable(canonicalPath: "/usr/bin/ssh", assurance: .independentlyProtected),
              descendantScope: .subtree, destination: .credentialConsumer, operationContext: "ssh"
          ),
          credentials: credentials(200),
          durationChoices: GrantDurationChoices.offered(requestedTTLSeconds: nil), ssh: ssh
      ))
      checkFitted("SSH panel, details closed", sshPanel, count: 0)
      button("Show details", in: sshPanel)?.performClick(nil)
      checkFitted("SSH panel, 200 keys' details", sshPanel, count: 1, mustScroll: true)
      button("Hide details", in: sshPanel)?.performClick(nil)
      checkFitted("SSH panel, details closed again", sshPanel, count: 0)
      withExtendedLifetime(sshPanel) {}
  }
#endif
