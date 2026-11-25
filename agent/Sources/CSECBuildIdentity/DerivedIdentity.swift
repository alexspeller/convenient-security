// The names csec derives from its build identity (BuildIdentity.swift, generated
// from identity.xcconfig), so a build under another Apple team changes them all
// by changing that one file.
extension CSECBuildIdentity {
    /// The Keychain access group csecd's provisioning profile grants.
    public static let keychainAccessGroup = "\(teamIdentifier).\(identifier)"
    /// The one CloudKit container the Mac and the paired iPhone share.
    public static let cloudKitContainer = "iCloud.\(identifier)"

    /// `identifier.suffix`: a component's signing identifier, a Keychain
    /// service or another name under csec's own prefix.
    public static func named(_ suffix: String) -> String {
        "\(identifier).\(suffix)"
    }
}
