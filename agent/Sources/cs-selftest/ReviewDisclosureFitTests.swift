import ConvenientSecurity
import Foundation
#if canImport(AppKit)
  import AppKit
  import LocalAuthentication
#endif

/// An opened disclosure grows its panel to show everything it holds, as the
/// release panel's delivery details always did; it scrolls only in what the
/// screen leaves once the grown panel would no longer fit (csec-kua.16, where
/// the SSH panel's "Show details" sat in a fixed 140-point peephole).
func reviewDisclosureFitTests() async {
    print("\n# Opened disclosures grow the panel; scroll only past the screen (csec-kua.16)")
    disclosureFitRuleTests()
    screenFitRuleTests()
    #if canImport(AppKit) && canImport(LocalAuthenticationEmbeddedUI)
      await MainActor.run {
        disclosureFitPanelTests()
        commandFitPanelTests()
        listFitPanelTests()
      }
    #endif
}

private func disclosureFitRuleTests() {
    let visible = CGRect(x: 0, y: 80, width: 1_440, height: 820)
    check(ReviewDisclosureFit.originY(top: 860, height: 600, visibleFrame: visible) == 260,
          "disclosure fit: a panel that still fits keeps its top edge")
    check(ReviewDisclosureFit.originY(top: 860, height: 800, visibleFrame: visible) == 80,
          "disclosure fit: a panel that would run off the bottom moves up onto the screen")
    check(ReviewDisclosureFit.originY(top: 860, height: 1_000, visibleFrame: visible) == -100,
          "disclosure fit: a panel taller than the screen keeps its title bar on screen")
    check(ReviewDisclosureFit.originY(top: 860, height: 800, visibleFrame: nil) == 60,
          "disclosure fit: with no screen, the top edge stays")
}

#if canImport(AppKit) && canImport(LocalAuthenticationEmbeddedUI)
  private let fitCaller = CallerInfo(pid: 51, startTime: 9, description: "cs-selftest fixture (pid 51)")

  private func fitSSHReview(references: [String]) -> AccessPolicyReview {
      let ssh = SSHAccessReviewDetails(
          hostNames: ["production.example.com", "staging.example.com", "third.example.com"],
          remoteUser: "deploy", keyLabel: "work", keyAlgorithm: "ssh-ed25519")
      return AccessPolicyReview(
          caller: fitCaller, reason: ssh.reason,
          plan: DeliveryPlan(
              mechanism: .credentialProtocol,
              executable: PlannedExecutable(canonicalPath: "/usr/bin/ssh", assurance: .independentlyProtected),
              descendantScope: .subtree, destination: .credentialConsumer, operationContext: "ssh"
          ),
          credentials: [PolicyReviewCredential(references: references.map { try! SecretRef($0) })],
          durationChoices: GrantDurationChoices.offered(requestedTTLSeconds: nil), ssh: ssh
      )
  }

  @MainActor
  private func disclosureFitPanelTests() {
      NSApplication.shared.setActivationPolicy(.accessory)
      func all(_ view: NSView) -> [NSView] { [view] + view.subviews.flatMap(all) }
      func button(_ title: String, in panel: ApprovalPanelInspection) -> NSButton? {
          all(panel.window.contentView ?? NSView()).compactMap { $0 as? NSButton }.first { $0.title == title }
      }
      let visibleHeight = NSScreen.main?.visibleFrame.height

      // One SSH key, as a real signing request has, and a card tall enough
      // that the old card scroller would have nested inside the details.
      let fixtures: [(String, [String])] = [
          ("one key", ["csec://ssh-keys/id_ed25519"]),
          ("tall card", (1...40).map { "csec://ssh-keys/key_\($0)" }),
      ]
      for (name, references) in fixtures {
          let panel = ApprovalPanelInspection.access(fitSSHReview(references: references))
          let window = panel.window
          let collapsed = window.frame.height
          guard let show = button("Show details", in: panel) else {
              check(false, "SSH panel (\(name)): has a Show details disclosure")
              continue
          }
          show.performClick(nil)
          window.contentView?.layoutSubtreeIfNeeded()
          let scrollers = all(window.contentView ?? NSView()).compactMap { $0 as? NSScrollView }
          guard let details = scrollers.first(where: { scroll in
              all(scroll.documentView ?? NSView()).contains { ($0 as? NSTextField)?.stringValue == "Requested by" }
          }), let document = details.documentView else {
              check(false, "SSH panel (\(name)): the opened details hold the delivery grid")
              continue
          }
          check(!all(document).dropFirst().contains { $0 is NSScrollView },
                "SSH panel (\(name)): no scroller nests inside the details' own")
          // Whole when the screen has room, else filling exactly the screen
          // with its cue showing (`ReviewScreenFit`; the list checks are in
          // `listFitPanelTests`).
          let natural = document.frame.height
          let cueShown = details.superview?.subviews.contains {
              ($0 as? NSTextField)?.identifier == ReviewFittedList.overflowCueIdentifier && !$0.isHidden
          } ?? false
          if !cueShown {
              check(abs(details.frame.height - natural) < 1,
                    "SSH panel (\(name)): the details are as tall as their content (\(details.frame.height) vs \(natural))")
              check(abs(window.frame.height - (collapsed + 8 + details.frame.height)) < 1,
                    "SSH panel (\(name)): the window grows by the opened details")
          } else if let visibleHeight {
              check(abs(window.frame.height - visibleHeight) < 1 || details.frame.height <= ReviewDisclosureFit.minimumHeight + 1,
                    "SSH panel (\(name)): scrolling details fill exactly what the screen leaves")
          }
          if name == "one key" {
              check(natural > 140, "SSH panel: the fixture's details are taller than the old 140-point box")
              if cueShown {
                  print("  note: this screen (\(visibleHeight ?? 0) pt) is too short to show the one-key details whole")
              }
          }
          if let visible = NSScreen.main?.visibleFrame, window.frame.height <= visible.height {
              check(window.frame.minY >= visible.minY - 0.5,
                    "SSH panel (\(name)): the grown window stays above the bottom of the screen")
          }
          button("Hide details", in: panel)?.performClick(nil)
          check(abs(window.frame.height - collapsed) < 1, "SSH panel (\(name)): hiding the details restores the window")
          withExtendedLifetime(panel) {}
      }

      // The release panel's delivery details keep growing the window, unscrolled.
      let release = ApprovalPanelInspection.access(AccessPolicyReview(
          caller: fitCaller, reason: "run migrations",
          plan: DeliveryPlan(
              mechanism: .directHeap,
              executable: PlannedExecutable(canonicalPath: "/usr/bin/ruby", assurance: .independentlyProtected),
              descendantScope: .subtree, destination: .localDevelopment,
              requestedTTLSeconds: nil, operationContext: "run migrations"
          ),
          commandLine: "bin/rails db:migrate",
          credentials: [PolicyReviewCredential(references: [try! SecretRef("csec://dev/API_TOKEN")])],
          durationChoices: GrantDurationChoices.offered(requestedTTLSeconds: nil)
      ))
      let releaseCollapsed = release.window.frame.height
      button("Show delivery details", in: release)?.performClick(nil)
      check(release.window.frame.height > releaseCollapsed + 100,
            "release panel: opening delivery details grows the window")
      check(!all(release.window.contentView ?? NSView()).contains { view in
          (view as? NSScrollView).map { scroll in
              all(scroll.documentView ?? NSView()).contains { ($0 as? NSTextField)?.stringValue == "Requested by" }
          } ?? false
      }, "release panel: the delivery grid is not in a scroller")
      withExtendedLifetime(release) {}
  }
#endif
