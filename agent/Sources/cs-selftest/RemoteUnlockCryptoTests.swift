import CryptoKit
import CSECRemoteApproval
import Foundation

/// The phone-held unlock factor, end to end with a software key standing in for
/// the phone's Secure Enclave key agreement (the same `SharedSecret` API).
func remoteUnlockCryptoTests() {
  let binding = Data("mac:11111111-1111-1111-1111-111111111111|phone:22222222-2222-2222-2222-222222222222".utf8)
  let phone = P256.KeyAgreement.PrivateKey()
  let otherPhone = P256.KeyAgreement.PrivateKey()

  guard let enrolled = try? RemoteUnlockCrypto.enroll(
    phoneKeyAgreementPublicKeyX963: phone.publicKey.x963Representation,
    binding: binding
  ) else {
    check(false, "remote unlock: enrollment succeeds for a valid phone key")
    return
  }
  let enrollment = enrolled.enrollment
  let remotePublic = enrolled.remoteKey.publicKey.compressedRepresentation

  // The blinding and its inverse over many fresh scalars: every one must
  // unblind to the enrollment's secret and open the same key.
  var roundTrips = 0
  var answersDiffer = true
  var previousAnswer: Data?
  var previousPoint: Data?
  var pointsDiffer = true
  for _ in 0..<64 {
    guard let challenge = try? RemoteUnlockCrypto.challenge(for: enrollment),
          let answer = try? RemoteUnlockCrypto.answer(
            blindedPoint: challenge.blindedPoint,
            agree: { try phone.sharedSecretFromKeyAgreement(with: $0) }
          ),
          let opened = try? RemoteUnlockCrypto.openRemoteKey(
            enrollment: enrollment, challenge: challenge, answer: answer, binding: binding
          ) else { continue }
    if opened.publicKey.compressedRepresentation == remotePublic { roundTrips += 1 }
    if answer == previousAnswer { answersDiffer = false }
    if challenge.blindedPoint == previousPoint { pointsDiffer = false }
    previousAnswer = answer
    previousPoint = challenge.blindedPoint
  }
  check(roundTrips == 64, "remote unlock: 64 blinded requests each unblind and open the remote key")
  check(pointsDiffer, "remote unlock: every request carries a fresh blinded point")
  check(answersDiffer, "remote unlock: every answer differs, so no mailbox value repeats")

  remoteUnlockScalarInverseKnownAnswers()

  // The phone's answer is never the reusable secret: x(p·E) itself.
  if let challenge = try? RemoteUnlockCrypto.challenge(for: enrollment),
     let answer = try? RemoteUnlockCrypto.answer(
       blindedPoint: challenge.blindedPoint,
       agree: { try phone.sharedSecretFromKeyAgreement(with: $0) }
     ),
     let ephemeral = try? P256.KeyAgreement.PublicKey(
       compressedRepresentation: enrollment.ephemeralPublicKey
     ),
     let direct = try? phone.sharedSecretFromKeyAgreement(with: ephemeral) {
    let reusable = direct.withUnsafeBytes { Data($0) }
    check(answer != reusable, "remote unlock: what crosses the relay is not the unwrap secret")
  } else {
    check(false, "remote unlock: direct-secret comparison ran")
  }

  // Everything that must not open.
  func refusesToOpen(
    _ label: String,
    challengeFor answerEnrollment: RemoteUnlockCrypto.Enrollment = enrollment,
    answeringKey: P256.KeyAgreement.PrivateKey = phone,
    openBinding: Data = binding,
    tamper: (Data) -> Data = { $0 },
    swapChallenge: Bool = false
  ) {
    do {
      let challenge = try RemoteUnlockCrypto.challenge(for: answerEnrollment)
      let answer = tamper(try RemoteUnlockCrypto.answer(
        blindedPoint: challenge.blindedPoint,
        agree: { try answeringKey.sharedSecretFromKeyAgreement(with: $0) }
      ))
      let openingChallenge = swapChallenge
        ? try RemoteUnlockCrypto.challenge(for: enrollment) : challenge
      _ = try RemoteUnlockCrypto.openRemoteKey(
        enrollment: enrollment, challenge: openingChallenge, answer: answer, binding: openBinding
      )
      check(false, "remote unlock: \(label)")
    } catch {
      check(true, "remote unlock: \(label)")
    }
  }
  refusesToOpen("another phone's answer does not open the key", answeringKey: otherPhone)
  refusesToOpen("an answer to a different request's blinding does not open", swapChallenge: true)
  refusesToOpen("an enrollment moved to another pairing does not open",
                openBinding: Data("mac:other|phone:other".utf8))
  refusesToOpen("a tampered answer does not open", tamper: { answer in
    var bytes = [UInt8](answer)
    bytes[31] ^= 0x01
    return Data(bytes)
  })
  refusesToOpen("a truncated answer is refused", tamper: { $0.prefix(31) })

  if let other = try? RemoteUnlockCrypto.enroll(
    phoneKeyAgreementPublicKeyX963: phone.publicKey.x963Representation, binding: binding
  ) {
    refusesToOpen("an answer computed against another enrollment does not open",
                  challengeFor: other.enrollment)
  }

  // A blinded point the phone would be asked to multiply must be on the curve.
  checkThrows("remote unlock: the phone refuses a point that is not on P-256") {
    _ = try RemoteUnlockCrypto.answer(
      blindedPoint: Data([0x02]) + Data(repeating: 0xff, count: 32),
      agree: { try phone.sharedSecretFromKeyAgreement(with: $0) }
    )
  }
  checkThrows("remote unlock: the phone refuses a point of the wrong size") {
    _ = try RemoteUnlockCrypto.answer(
      blindedPoint: Data(repeating: 0x02, count: 32),
      agree: { try phone.sharedSecretFromKeyAgreement(with: $0) }
    )
  }
  checkThrows("remote unlock: enrollment refuses a malformed phone key") {
    _ = try RemoteUnlockCrypto.enroll(
      phoneKeyAgreementPublicKeyX963: Data(repeating: 0x04, count: 65), binding: binding
    )
  }

  // Sealing to the remote key: writes never need the phone.
  let context = Data("native|documents|development|\(enrollment.enrollmentID)".utf8)
  let payload = Data("synthetic store key record".utf8)
  do {
    let sealed = try RemoteUnlockCrypto.seal(
      payload, toRemotePublicKey: enrollment.remotePublicKey, context: context
    )
    let again = try RemoteUnlockCrypto.seal(
      payload, toRemotePublicKey: enrollment.remotePublicKey, context: context
    )
    check(sealed != again, "remote unlock: each seal uses a fresh sender key")
    check(
      (try? RemoteUnlockCrypto.open(sealed, remoteKey: enrolled.remoteKey, context: context))
        == payload,
      "remote unlock: a sealed box opens with the remote key")
    check(
      (try? RemoteUnlockCrypto.open(
        sealed, remoteKey: enrolled.remoteKey,
        context: Data("native|documents|production|\(enrollment.enrollmentID)".utf8))) == nil,
      "remote unlock: a box moved to another name does not open")
    check(
      (try? RemoteUnlockCrypto.open(
        sealed, remoteKey: P256.KeyAgreement.PrivateKey(), context: context)) == nil,
      "remote unlock: another key does not open a sealed box")
    var tampered = [UInt8](sealed)
    tampered[tampered.count - 1] ^= 0x80
    check(
      (try? RemoteUnlockCrypto.open(
        Data(tampered), remoteKey: enrolled.remoteKey, context: context)) == nil,
      "remote unlock: a tampered box does not open")
    var wrongFormat = [UInt8](sealed)
    wrongFormat[0] = 0x02
    check(
      (try? RemoteUnlockCrypto.open(
        Data(wrongFormat), remoteKey: enrolled.remoteKey, context: context)) == nil,
      "remote unlock: an unknown box format is refused")
    check(
      (try? RemoteUnlockCrypto.open(
        sealed.prefix(34), remoteKey: enrolled.remoteKey, context: context)) == nil,
      "remote unlock: a truncated box is refused")
  } catch {
    check(false, "remote unlock: sealing to the remote key succeeds (\(error))")
  }

  // The enrollment record carries no usable secret on its own: without the
  // phone, nothing in it opens a box sealed to R.
  if let encoded = try? JSONEncoder().encode(enrollment),
     let text = String(data: encoded, encoding: .utf8) {
    let rawScalar = enrolled.remoteKey.rawRepresentation
    check(encoded.range(of: rawScalar) == nil
            && !text.contains(rawScalar.base64EncodedString()),
          "remote unlock: the stored enrollment does not contain the remote private key")
  }
}

/// r⁻¹ mod n against answers computed independently (Python's pow(r, -1, n)),
/// including the edges of the range and a value whose limbs differ from n's
/// at every position. Scalars outside 1..<n are refused.
private func remoteUnlockScalarInverseKnownAnswers() {
  func scalar(_ hex: String) -> Data {
    var bytes = [UInt8]()
    var index = hex.startIndex
    while index < hex.endIndex {
      let next = hex.index(index, offsetBy: 2)
      bytes.append(UInt8(hex[index..<next], radix: 16) ?? 0)
      index = next
    }
    return Data(bytes)
  }
  let order = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"
  let knownAnswers: [(label: String, r: String, inverse: String)] = [
    ("r = 1", String(repeating: "0", count: 63) + "1", String(repeating: "0", count: 63) + "1"),
    ("r = 2 gives (n+1)/2", String(repeating: "0", count: 63) + "2",
     "7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a9"),
    ("r = (n+1)/2 gives 2", "7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a9",
     String(repeating: "0", count: 63) + "2"),
    ("r = 3", String(repeating: "0", count: 63) + "3",
     "aaaaaaaa00000000aaaaaaaaaaaaaaaa7def51c91a0fbf034d26872ca84218e1"),
    ("r = n−1 gives n−1", "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
     "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550"),
    ("a scalar with every limb set", "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
     "ddbe67fb14714ab5c0d909913a16bb6a2af63adfab8d3a5be98658011a910777"),
  ]
  for answer in knownAnswers {
    let inverse = try? RemoteUnlockCrypto.scalarInverse(ofBigEndian: scalar(answer.r))
    check(inverse == scalar(answer.inverse), "remote unlock: scalar inverse known answer, \(answer.label)")
  }
  var involutions = 0
  for _ in 0..<64 {
    let blinding = P256.KeyAgreement.PrivateKey().rawRepresentation
    if let inverse = try? RemoteUnlockCrypto.scalarInverse(ofBigEndian: blinding),
       inverse != blinding,
       (try? RemoteUnlockCrypto.scalarInverse(ofBigEndian: inverse)) == blinding {
      involutions += 1
    }
  }
  check(involutions == 64, "remote unlock: inverting 64 random scalars twice gives each one back")
  checkThrows("remote unlock: the scalar inverse refuses 0") {
    _ = try RemoteUnlockCrypto.scalarInverse(ofBigEndian: Data(count: 32))
  }
  checkThrows("remote unlock: the scalar inverse refuses n") {
    _ = try RemoteUnlockCrypto.scalarInverse(ofBigEndian: scalar(order))
  }
  checkThrows("remote unlock: the scalar inverse refuses a value above n") {
    _ = try RemoteUnlockCrypto.scalarInverse(ofBigEndian: Data(repeating: 0xff, count: 32))
  }
  checkThrows("remote unlock: the scalar inverse refuses a scalar of the wrong size") {
    _ = try RemoteUnlockCrypto.scalarInverse(ofBigEndian: Data(repeating: 0x01, count: 31))
  }
}
