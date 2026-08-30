# Convenient Security Approval for iPhone

This is the opt-in companion app for the signed protocol in
`agent/Sources/CSECRemoteApproval`. It contains no secret provider and receives
no resolved credential values. It verifies a pinned Mac signature, renders the
frozen value-free review, then uses a Face-ID-gated Secure Enclave P-256 key to
sign one exact Approve or Deny response.

`project.yml` is the source of the Xcode project:

```sh
cd ios
xcodegen generate
open ConvenientSecurityApproval.xcodeproj
```

A Debug iPhone Simulator build uses an explicitly insecure software-key backend
and can inject a locally signed sample request; it needs full Xcode and XcodeGen
but no Apple portal or iCloud setup. Physical testing retains the Secure Enclave
path and additionally requires the registered App ID/container, matching
Development provisioning on the Mac and phone, and enrolled Face ID. The exact
simulator steps, CloudKit/APNs setup, and physical acceptance matrix are in
[`../docs/remote-approval.md`](../docs/remote-approval.md). Do not commit personal
provisioning profiles or generated signing state.
