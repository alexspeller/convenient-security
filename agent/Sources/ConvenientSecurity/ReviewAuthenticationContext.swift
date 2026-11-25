#if canImport(LocalAuthentication)
  @preconcurrency import LocalAuthentication

  /// The one place an approval dialog's `LAContext` is built.
  ///
  /// csec draws three human approval dialogs — the secret-access review, the SSH
  /// signing review (the same class, its own layout), and the sudo review in the
  /// PAM helper — in two processes that share no panel code path. Each of them
  /// also presents its prompt more than once: a prompt cancelled behind the lock
  /// screen is re-presented on a rebuilt context after unlock, and one that lost
  /// the focus while Touch ID was armed is re-armed on a rebuilt context when it
  /// is key again (`ReviewFocusRecovery`). Every one of those
  /// contexts comes from here, so the properties below are one stated invariant
  /// rather than a decision each surface makes again.
  public enum ReviewAuthenticationContext {
    /// Which approval dialog a context belongs to. The secret-access and SSH
    /// signing reviews are one class with two layouts (the automation review is
    /// a variant of the secret-access surface), but they are named apart so each
    /// surface's factory path can be asserted on its own.
    public enum Surface: CaseIterable {
      case secretAccess
      case sshSigning
      case sudo

      /// The title Apple's sheet gives the button that refuses it. Refusing a
      /// csec review is the whole decision ("Deny"); refusing the sudo review
      /// hands sudo back to its own password prompt ("Use Password…").
      public var cancelTitle: String {
        switch self {
        case .secretAccess, .sshSigning:
          return "Deny"
        case .sudo:
          return "Use Password…"
        }
      }
    }

    /// A context configured for `surface`, ready to evaluate.
    public static func make(for surface: Surface) -> LAContext {
      let context = LAContext()
      context.localizedCancelTitle = surface.cancelTitle
      // No password fallback inside Apple's sheet: the panel behind it is what
      // the human is reading, and each surface owns its own fallback path.
      context.localizedFallbackTitle = ""
      // Touch ID reuse is zero on every surface — stated here, not inherited
      // from the OS default. `touchIDAuthenticationAllowableReuseDuration`
      // accepts a biometric match the *device lock screen* has already taken:
      // "If the device was successfully unlocked by biometry within this time
      // interval, then biometric authentication on this context will succeed
      // automatically and the reply block will be called without prompting user
      // for Touch ID or Face ID… This property is meant only for reusing
      // biometric matches from the device lock screen. It does not allow
      // reusing previous biometric matches in application or between
      // applications." (LAContext.h). So a nonzero value would let an approval
      // panel that appears shortly after the Mac is unlocked with Touch ID
      // succeed on its own: no finger on the sensor, nothing read, no decision
      // — the panel would have authorized a request the human never saw. What
      // legitimately answers "don't ask me twice" is a csec grant, which is
      // bound to the process or session that was actually reviewed.
      context.touchIDAuthenticationAllowableReuseDuration = 0
      return context
    }
  }
#endif
