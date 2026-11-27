import ConvenientSecurity
import Foundation
#if canImport(AppKit)
  import AppKit
#endif

#if canImport(AppKit) && canImport(LocalAuthenticationEmbeddedUI)
  /// A command a panel asks the human to verify is shown whole, as tall as the
  /// screen allows, and says so when it still has to scroll (csec-0.58, where
  /// the sudo card clipped 64 arguments to 12 lines behind a fading scroller).
  /// The sudo card, the access panel's full command line and the automation
  /// layout's exact command all draw it through `ReviewCommandText`.
  @MainActor
  func commandFitPanelTests() {
      NSApplication.shared.setActivationPolicy(.accessory)
      func all(_ view: NSView) -> [NSView] { [view] + view.subviews.flatMap(all) }
      func commandScroll(_ panel: ApprovalPanelInspection) -> NSScrollView? {
          all(panel.window.contentView ?? NSView()).compactMap { $0 as? NSScrollView }
              .first { $0.documentView is NSTextView && !$0.isHiddenOrHasHiddenAncestor }
      }
      func cue(_ panel: ApprovalPanelInspection) -> NSTextField? {
          all(panel.window.contentView ?? NSView()).compactMap { $0 as? NSTextField }
              .first { $0.identifier == ReviewCommandText.overflowCueIdentifier }
      }
      let visibleHeight = NSScreen.main?.visibleFrame.height

      /// The facts every fitted command must hold: either all of it is in
      /// view with no cue, or the panel fills no more than the screen, the
      /// scroller cannot fade, and the cue says the command continues.
      func checkFitted(_ name: String, _ panel: ApprovalPanelInspection, mustScroll: Bool? = nil) {
          panel.window.contentView?.layoutSubtreeIfNeeded()
          guard let scroll = commandScroll(panel), let text = scroll.documentView as? NSTextView,
              let layout = text.layoutManager, let container = text.textContainer,
              let cue = cue(panel)
          else {
              check(false, "\(name): shows the command in its scrolling text, with an overflow cue")
              return
          }
          layout.ensureLayout(for: container)
          let content = ceil(layout.usedRect(for: container).height) + text.textContainerInset.height * 2
          let shown = scroll.contentView.bounds.height
          let scrolls = content > shown + 1
          check(scrolls == !cue.isHidden,
                "\(name): the cue shows exactly when the command scrolls (content \(content), shown \(shown))")
          if let mustScroll {
              check(scrolls == mustScroll, "\(name): \(mustScroll ? "scrolls" : "shows whole") on this screen")
          }
          if scrolls {
              // The minimum is the scroll view's frame, which the fit rule
              // sizes; a bordered command's clip is two points shorter.
              let frame = scroll.frame.height
              check(frame >= ReviewDisclosureFit.minimumHeight - 1,
                    "\(name): a scrolling command keeps at least the minimum height (\(frame), showing \(shown))")
              check(scroll.scrollerStyle == .legacy && !scroll.autohidesScrollers && scroll.hasVerticalScroller,
                    "\(name): a scrolling command's scroller is always drawn")
              check(cue.stringValue == ReviewCommandText.overflowCueText,
                    "\(name): the cue says the command continues")
              if let visibleHeight {
                  // A screen too short for the rest of the panel and the
                  // minimum (a 1024 by 768 display leaves 674 points) still
                  // gives the command the minimum, so the panel runs past it.
                  if frame <= ReviewDisclosureFit.minimumHeight + 1, panel.window.frame.height > visibleHeight + 1 {
                      print("  note: this screen (\(visibleHeight) pt) is too short for \(name) "
                            + "with the minimum (\(panel.window.frame.height) pt)")
                  } else {
                      check(panel.window.frame.height <= visibleHeight + 1,
                            "\(name): the panel grows only to the screen (\(panel.window.frame.height) vs \(visibleHeight))")
                      check(panel.window.frame.height >= visibleHeight - 1,
                            "\(name): a scrolling command uses all the height the screen leaves")
                  }
              }
          } else {
              check(text.frame.height <= shown + 1, "\(name): nothing of the command is clipped")
          }
      }

      let terminal = TerminalSessionContext(
          application: "iTerm2", title: "deploy — ~/project", location: "window 1, tab 2", tty: "ttys001")
      func sudo(_ command: String) -> ApprovalPanelInspection {
          .sudo(SudoAuthorizationReviewRequest(
              submittedCommand: command, workingDirectory: "/Users/example/project", terminal: "/dev/ttys001"),
              terminal: terminal)
      }

      checkFitted("sudo panel, short command", sudo("sudo /usr/bin/true"), mustScroll: false)
      // As many arguments as the PAM module renders: the old 180-point card
      // showed twelve of these lines.
      let files = (1...(SudoCommandDisplay.maximumArguments - 2)).map {
          String(format: "/Library/LaunchDaemons/com.example.fleet-agent.worker-%02d.plist", $0)
      }
      let longArgv = sudo((["sudo", "/usr/sbin/chown", "root:wheel"] + files).joined(separator: " "))
      checkFitted("sudo panel, 64 arguments", longArgv)
      // Only a screen that leaves the command more than 180 points can show
      // more than the old card did.
      if let scroll = commandScroll(longArgv) {
          let shown = scroll.contentView.bounds.height
          let room = (visibleHeight ?? .greatestFiniteMagnitude) - (longArgv.window.frame.height - scroll.frame.height)
          if room > 182 {
              check(shown > 180, "sudo panel, 64 arguments: more of the command shows than the old 180-point card")
          }
      }
      // The longest command the frame carries cannot fit any screen.
      let longest = "sudo /bin/echo " + String(
          repeating: "argument ", count: (SudoAuthorizationReviewWire.maximumCommandBytes - 15) / 9)
      check(longest.utf8.count <= SudoAuthorizationReviewWire.maximumCommandBytes,
            "sudo panel: the longest fixture is a command the frame can carry")
      checkFitted("sudo panel, longest command", sudo(longest), mustScroll: true)

      // The access panel's full command line, behind its disclosure.
      let caller = CallerInfo(pid: 51, startTime: 9, description: "cs-selftest fixture (pid 51)")
      let plan = DeliveryPlan(
          mechanism: .directHeap,
          executable: PlannedExecutable(canonicalPath: "/usr/bin/ruby", assurance: .independentlyProtected),
          descendantScope: .subtree, destination: .localDevelopment,
          requestedTTLSeconds: nil, operationContext: "run migrations"
      )
      let credentials = [PolicyReviewCredential(references: [try! SecretRef("csec://dev/API_TOKEN")])]
      for (name, words) in [("long", 120), ("longest", 900)] {
          let command = "bin/rails runner " + Array(repeating: "Migration.run", count: words).joined(separator: " ")
          let panel = ApprovalPanelInspection.access(AccessPolicyReview(
              caller: caller, reason: "run migrations", plan: plan, commandLine: command,
              credentials: credentials, durationChoices: GrantDurationChoices.offered(requestedTTLSeconds: nil)
          ))
          let disclosure = all(panel.window.contentView ?? NSView()).compactMap { $0 as? NSButton }
              .first { $0.title == "Show full command" }
          guard let disclosure else {
              check(false, "access panel, \(name) command: has a Show full command disclosure")
              continue
          }
          check(cue(panel)?.isHidden == true, "access panel, \(name) command: no cue before the command opens")
          disclosure.performClick(nil)
          checkFitted("access panel, \(name) full command", panel, mustScroll: name == "longest" ? true : nil)
          // The rest of this panel takes some 620 to 650 points, by whether
          // the Mac can take a touch and what else it draws, so a screen just
          // over 1000 points tall legitimately leaves the command 360 or less
          // (csec-0.85). The old peephole shows only on a screen leaving more.
          if name == "long", let scroll = commandScroll(panel), let visibleHeight {
              let shown = scroll.contentView.bounds.height
              let room = visibleHeight - (panel.window.frame.height - shown)
              if room > 361 {
                  check(shown > 360 || cue(panel)?.isHidden == true,
                        "access panel, long full command: not capped at the old 360 points (\(shown) of \(room))")
              }
          }
          disclosure.performClick(nil)
          check(cue(panel)?.isHidden == true, "access panel, \(name) command: hiding the command hides its cue")
          withExtendedLifetime(panel) {}
      }

      // The automation layout's exact command, shown from the start.
      for (name, count) in [("short", 1), ("long", 60), ("longest", 64)] {
          let argument = count == 64 ? String(repeating: "a", count: 120) : "--flag"
          let job = AutomationJob(
              id: UUID().uuidString.lowercased(), revision: UUID().uuidString.lowercased(),
              name: "backup", reason: "nightly backup", references: ["csec://dev/X"],
              command: AutomationCommand(
                  executable: PlannedExecutable(canonicalPath: "/usr/bin/true", assurance: .unverified),
                  commandLine: ["/usr/bin/true"] + Array(repeating: argument, count: count - 1),
                  workingDirectory: "/tmp", commandDigest: String(repeating: "0", count: 64)
              ),
              minimumIntervalSeconds: 60, maximumRuntimeSeconds: 60, consumerTrust: .mutableInterpreted,
              createdAt: Date(), updatedAt: Date()
          )
          let panel = ApprovalPanelInspection.access(AccessPolicyReview(
              caller: caller, reason: job.reason, plan: plan, credentials: credentials,
              automation: AutomationReviewDetails(job: job)))
          all(panel.window.contentView ?? NSView()).compactMap { $0 as? NSButton }
              .first { $0.title == "Show command and security details" }?.performClick(nil)
          checkFitted("automation panel, \(name) command", panel, mustScroll: name == "short" ? false : nil)
          if name == "long", let scroll = commandScroll(panel) {
              let room = (visibleHeight ?? .greatestFiniteMagnitude) - (panel.window.frame.height - scroll.frame.height)
              if room > 89 {
                  check(scroll.frame.height > 88, "automation panel, long command: taller than the old 88-point box")
              }
          }
          withExtendedLifetime(panel) {}
      }
  }
#endif
