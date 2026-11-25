import CryptoKit
import Foundation

/// The phone-held factor that lets a verified phone approval open csec's cold
/// storage on a Mac that has seen no Touch ID since csecd started.
///
/// At enrollment the Mac makes a remote-unlock key pair R and wraps R's private
/// half under x(e·P), where P is the phone's Face-ID-gated Secure Enclave
/// key-agreement key and e is an ephemeral scalar the Mac discards at once. Only
/// the phone can recompute that secret, as x(p·E). Everything the Mac later
/// needs to open cold storage is sealed to R's public half, so writes never
/// need the phone.
///
/// A request does not ask the phone for x(p·E) directly: that value would be a
/// reusable unwrap key sitting in the mailbox. The Mac blinds E with a fresh
/// scalar r and sends B = r·E; the phone answers Z = x(p·B), which is useless
/// without r; the Mac recovers x(p·E) as x(r⁻¹·Z). The relay therefore sees a
/// uniformly random point and an answer that opens nothing, and the phone sees
/// nothing it could reuse — as long as r stays secret: r together with Z
/// yields x(p·E), the enrollment's static unwrap secret. Every step is P-256
/// key agreement from CryptoKit; the only arithmetic done here is r⁻¹ mod n,
/// which is branch-free so its timing reveals nothing about r (`Scalar`), and
/// whose result is checked, so a mistake in it fails closed — the unwrap then
/// fails authentication.
///
/// ECDH output is the x-coordinate only, and x(k·Q) == x(k·(−Q)), so a point
/// rebuilt from an x-coordinate with either sign gives the same answer.
public enum RemoteUnlockCrypto {
    /// HKDF info for the key that wraps R's private half.
    static let wrapInfo = Data("csec.remote-unlock.wrap.v1".utf8)
    /// HKDF info for material sealed to R's public half.
    static let sealInfo = Data("csec.remote-unlock.seal.v1".utf8)
    /// Leading byte of a sealed box, so the format can change without guessing.
    static let sealFormat: UInt8 = 1
    static let compressedPointBytes = 33
    static let scalarBytes = 32

    public enum Failure: Error, Equatable, Sendable {
        /// A point or x-coordinate that is not on P-256, or has the wrong size.
        case invalidPoint
        /// A scalar outside 1..<n.
        case invalidScalar
        /// The wrapped remote key did not open: a different phone key, a
        /// different enrollment, an answer to another challenge, or tampering.
        case unwrapFailed
        /// A sealed box that is malformed or did not authenticate.
        case invalidSealedBox
        /// r·r⁻¹ ≢ 1 (mod n). Never expected; checked so a bug fails closed.
        case arithmeticSelfCheckFailed
    }

    /// What the Mac keeps between enrollment and every later cold unlock. It
    /// holds no usable secret: the wrapped key opens only with the phone's
    /// Face-ID-gated key agreement.
    public struct Enrollment: Codable, Equatable, Sendable {
        public let enrollmentID: String
        /// E = e·G, compressed. e itself was discarded at enrollment.
        public let ephemeralPublicKey: Data
        /// AES-GCM combined box holding R's 32-byte private scalar.
        public let wrappedRemoteKey: Data
        /// R's public half, compressed: what storage is sealed to.
        public let remotePublicKey: Data
        /// The phone key-agreement key the wrap is bound to, X9.63.
        public let phoneKeyAgreementPublicKey: Data
    }

    /// One request's blinding. The scalar never leaves the Mac; the point goes
    /// into the signed request.
    public struct Challenge: Sendable {
        let blindingScalar: Data
        /// B = r·E, compressed.
        public let blindedPoint: Data
    }

    /// Create a remote-unlock key pair wrapped to the phone's key-agreement key.
    /// `binding` is canonical bytes naming the pairing (Mac and phone device
    /// IDs); the wrap authenticates it, so an enrollment copied to another
    /// pairing does not open.
    public static func enroll(
        phoneKeyAgreementPublicKeyX963: Data,
        binding: Data,
        enrollmentID: String = UUID().uuidString.lowercased()
    ) throws -> (enrollment: Enrollment, remoteKey: P256.KeyAgreement.PrivateKey) {
        let phoneKey: P256.KeyAgreement.PublicKey
        do {
            phoneKey = try P256.KeyAgreement.PublicKey(
                x963Representation: phoneKeyAgreementPublicKeyX963
            )
        } catch {
            throw Failure.invalidPoint
        }
        let remoteKey = P256.KeyAgreement.PrivateKey()
        let ephemeral = P256.KeyAgreement.PrivateKey()
        let secret = bytes(try ephemeral.sharedSecretFromKeyAgreement(with: phoneKey))
        let ephemeralPublicKey = ephemeral.publicKey.compressedRepresentation
        let remotePublicKey = remoteKey.publicKey.compressedRepresentation
        let aad = wrapAuthenticatedData(
            enrollmentID: enrollmentID,
            ephemeralPublicKey: ephemeralPublicKey,
            remotePublicKey: remotePublicKey,
            phoneKeyAgreementPublicKey: phoneKeyAgreementPublicKeyX963,
            binding: binding
        )
        let box = try AES.GCM.seal(
            remoteKey.rawRepresentation,
            using: wrapKey(secret: secret, enrollmentID: enrollmentID),
            authenticating: aad
        )
        guard let combined = box.combined else { throw Failure.unwrapFailed }
        return (
            Enrollment(
                enrollmentID: enrollmentID,
                ephemeralPublicKey: ephemeralPublicKey,
                wrappedRemoteKey: combined,
                remotePublicKey: remotePublicKey,
                phoneKeyAgreementPublicKey: phoneKeyAgreementPublicKeyX963
            ),
            remoteKey
        )
    }

    /// A fresh blinding of the enrollment's E for one request.
    public static func challenge(for enrollment: Enrollment) throws -> Challenge {
        let ephemeral = try publicKey(compressed: enrollment.ephemeralPublicKey)
        let blinding = P256.KeyAgreement.PrivateKey()
        let x = bytes(try blinding.sharedSecretFromKeyAgreement(with: ephemeral))
        let blinded = try publicKey(x: x)
        return Challenge(
            blindingScalar: blinding.rawRepresentation,
            blindedPoint: blinded.compressedRepresentation
        )
    }

    /// The phone's side. Call it only for a blinded point carried in a request
    /// whose Mac signature has already verified, after the same Face ID that
    /// signs the approval; `agree` is the Secure Enclave key agreement.
    public static func answer(
        blindedPoint: Data,
        agree: (P256.KeyAgreement.PublicKey) throws -> SharedSecret
    ) throws -> Data {
        let point = try publicKey(compressed: blindedPoint)
        return bytes(try agree(point))
    }

    /// The Mac's side: unblind the phone's answer and open R.
    public static func openRemoteKey(
        enrollment: Enrollment,
        challenge: Challenge,
        answer: Data,
        binding: Data
    ) throws -> P256.KeyAgreement.PrivateKey {
        let answerPoint = try publicKey(x: answer)
        let inverse = try Scalar.inverse(ofBigEndian: challenge.blindingScalar)
        let unblinding = try P256.KeyAgreement.PrivateKey(rawRepresentation: inverse)
        let secret = bytes(try unblinding.sharedSecretFromKeyAgreement(with: answerPoint))
        let aad = wrapAuthenticatedData(
            enrollmentID: enrollment.enrollmentID,
            ephemeralPublicKey: enrollment.ephemeralPublicKey,
            remotePublicKey: enrollment.remotePublicKey,
            phoneKeyAgreementPublicKey: enrollment.phoneKeyAgreementPublicKey,
            binding: binding
        )
        let raw: Data
        do {
            raw = try AES.GCM.open(
                AES.GCM.SealedBox(combined: enrollment.wrappedRemoteKey),
                using: wrapKey(secret: secret, enrollmentID: enrollment.enrollmentID),
                authenticating: aad
            )
        } catch {
            throw Failure.unwrapFailed
        }
        guard let remoteKey = try? P256.KeyAgreement.PrivateKey(rawRepresentation: raw),
              remoteKey.publicKey.compressedRepresentation == enrollment.remotePublicKey else {
            throw Failure.unwrapFailed
        }
        return remoteKey
    }

    /// Seal `payload` to R's public half. `context` names what is sealed (for
    /// example the store and tier) and is authenticated, so a box moved to
    /// another name does not open.
    public static func seal(
        _ payload: Data,
        toRemotePublicKey remotePublicKey: Data,
        context: Data
    ) throws -> Data {
        let recipient = try publicKey(compressed: remotePublicKey)
        let sender = P256.KeyAgreement.PrivateKey()
        let senderPublicKey = sender.publicKey.compressedRepresentation
        let secret = bytes(try sender.sharedSecretFromKeyAgreement(with: recipient))
        let box = try AES.GCM.seal(
            payload,
            using: sealKey(
                secret: secret,
                senderPublicKey: senderPublicKey,
                remotePublicKey: remotePublicKey,
                context: context
            ),
            authenticating: context
        )
        guard let combined = box.combined else { throw Failure.invalidSealedBox }
        return Data([sealFormat]) + senderPublicKey + combined
    }

    /// Open a box sealed to R.
    public static func open(
        _ sealed: Data,
        remoteKey: P256.KeyAgreement.PrivateKey,
        context: Data
    ) throws -> Data {
        let headerBytes = 1 + compressedPointBytes
        guard sealed.count > headerBytes, sealed.first == sealFormat else {
            throw Failure.invalidSealedBox
        }
        let senderPublicKey = Data(sealed.dropFirst().prefix(compressedPointBytes))
        let combined = Data(sealed.dropFirst(headerBytes))
        let sender: P256.KeyAgreement.PublicKey
        do {
            sender = try publicKey(compressed: senderPublicKey)
        } catch {
            throw Failure.invalidSealedBox
        }
        let secret = bytes(try remoteKey.sharedSecretFromKeyAgreement(with: sender))
        do {
            return try AES.GCM.open(
                AES.GCM.SealedBox(combined: combined),
                using: sealKey(
                    secret: secret,
                    senderPublicKey: senderPublicKey,
                    remotePublicKey: remoteKey.publicKey.compressedRepresentation,
                    context: context
                ),
                authenticating: context
            )
        } catch {
            throw Failure.invalidSealedBox
        }
    }

    // MARK: - Helpers

    static func bytes(_ secret: SharedSecret) -> Data {
        secret.withUnsafeBytes { Data($0) }
    }

    static func publicKey(compressed: Data) throws -> P256.KeyAgreement.PublicKey {
        guard compressed.count == compressedPointBytes else { throw Failure.invalidPoint }
        do {
            return try P256.KeyAgreement.PublicKey(compressedRepresentation: compressed)
        } catch {
            throw Failure.invalidPoint
        }
    }

    /// A point with x-coordinate `x`; which of the two it is never matters.
    static func publicKey(x: Data) throws -> P256.KeyAgreement.PublicKey {
        guard x.count == scalarBytes else { throw Failure.invalidPoint }
        return try publicKey(compressed: Data([0x02]) + x)
    }

    private static func wrapKey(secret: Data, enrollmentID: String) -> SymmetricKey {
        HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: secret),
            salt: Data(enrollmentID.utf8),
            info: wrapInfo,
            outputByteCount: 32
        )
    }

    private static func sealKey(
        secret: Data,
        senderPublicKey: Data,
        remotePublicKey: Data,
        context: Data
    ) -> SymmetricKey {
        HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: secret),
            salt: senderPublicKey + remotePublicKey,
            info: sealInfo + context,
            outputByteCount: 32
        )
    }

    private static func wrapAuthenticatedData(
        enrollmentID: String,
        ephemeralPublicKey: Data,
        remotePublicKey: Data,
        phoneKeyAgreementPublicKey: Data,
        binding: Data
    ) -> Data {
        var data = Data()
        for field in [
            wrapInfo, Data(enrollmentID.utf8), ephemeralPublicKey, remotePublicKey,
            phoneKeyAgreementPublicKey, binding,
        ] {
            let count = UInt32(field.count)
            data.append(contentsOf: [
                UInt8((count >> 24) & 0xff), UInt8((count >> 16) & 0xff),
                UInt8((count >> 8) & 0xff), UInt8(count & 0xff),
            ])
            data.append(field)
        }
        return data
    }

    /// r⁻¹ mod n, the P-256 group order, as 32 big-endian bytes, for r in
    /// 1..<n given the same way. `openRemoteKey` unblinds with it; it is
    /// public so its arithmetic can be checked against known answers.
    public static func scalarInverse(ofBigEndian scalar: Data) throws -> Data {
        try Scalar.inverse(ofBigEndian: scalar)
    }


    /// Arithmetic modulo the P-256 group order n, just enough for r⁻¹.
    ///
    /// r must stay secret: with the phone's answer Z = x(p·r·E), which the
    /// relay sees, it yields x(p·E) = x(r⁻¹·Z), the enrollment's static unwrap
    /// secret. So nothing here branches on a secret value or indexes memory by
    /// one. Values are eight radix-2³² limbs held in 64-bit words, so every
    /// carry and borrow is a shift, never an overflow test; every conditional
    /// subtraction or addition computes both candidates and keeps one with a
    /// mask; and every loop runs a fixed number of times. Only the exponent
    /// n − 2, which is public, decides what the exponentiation does.
    ///
    /// r^(n−2) is computed with Montgomery multiplication, and the result is
    /// checked with a separate double-and-add multiplication, so a mistake in
    /// either fails closed instead of producing a wrong key.
    enum Scalar {
        static let limbCount = 8
        static let limbMask: UInt64 = 0xFFFF_FFFF
        /// n, little-endian.
        static let order: [UInt64] = [
            0xFC63_2551, 0xF3B9_CAC2, 0xA717_9E84, 0xBCE6_FAAD,
            0xFFFF_FFFF, 0xFFFF_FFFF, 0x0000_0000, 0xFFFF_FFFF,
        ]
        static let one: [UInt64] = [1, 0, 0, 0, 0, 0, 0, 0]
        /// −n⁻¹ mod 2³², for Montgomery reduction.
        static let montgomeryFactor: UInt64 = 0xEE00_BC4F
        /// 2⁵¹² mod n: multiplying by it enters the Montgomery domain.
        static let montgomerySquare: [UInt64] = [
            0xBE79_EEA2, 0x8324_4C95, 0x49BD_6FA6, 0x4699_799C,
            0x2B6B_EC59, 0x2845_B239, 0xF3D9_5620, 0x66E1_2D94,
        ]
        /// n − 2: n is prime, so r^(n−2) ≡ r⁻¹ (mod n).
        static let inverseExponent = subtract(order, [2, 0, 0, 0, 0, 0, 0, 0]).difference

        static func inverse(ofBigEndian scalar: Data) throws -> Data {
            let value = try limbs(bigEndian: scalar)
            // Whether r is in range is public (a blinding scalar always is);
            // computing it takes the same steps for every r.
            guard !isZero(value), lessThan(value, order) else { throw Failure.invalidScalar }
            let base = montgomeryMultiply(value, montgomerySquare)
            var power = montgomeryMultiply(one, montgomerySquare)
            for bit in stride(from: 255, through: 0, by: -1) {
                power = montgomeryMultiply(power, power)
                if bitOf(inverseExponent, bit) == 1 {
                    power = montgomeryMultiply(power, base)
                }
            }
            let result = montgomeryMultiply(power, one)
            guard isEqual(multiply(value, result), one) else {
                throw Failure.arithmeticSelfCheckFailed
            }
            return bigEndian(result)
        }

        static func limbs(bigEndian data: Data) throws -> [UInt64] {
            guard data.count == scalarBytes else { throw Failure.invalidScalar }
            let bytes = [UInt8](data)
            var limbs = [UInt64](repeating: 0, count: limbCount)
            for limb in 0..<limbCount {
                var value: UInt64 = 0
                for index in 0..<4 {
                    value = (value << 8) | UInt64(bytes[(limbCount - 1 - limb) * 4 + index])
                }
                limbs[limb] = value
            }
            return limbs
        }

        static func bigEndian(_ limbs: [UInt64]) -> Data {
            var bytes = [UInt8]()
            bytes.reserveCapacity(scalarBytes)
            for limb in stride(from: limbCount - 1, through: 0, by: -1) {
                for index in stride(from: 3, through: 0, by: -1) {
                    bytes.append(UInt8(truncatingIfNeeded: limbs[limb] >> UInt64(index * 8)))
                }
            }
            return Data(bytes)
        }

        /// Bit `bit` (0 = least significant) of `value`, as 0 or 1.
        static func bitOf(_ value: [UInt64], _ bit: Int) -> UInt64 {
            (value[bit / 32] >> UInt64(bit % 32)) & 1
        }

        /// `whenSet` when `bit` is 1, `otherwise` when it is 0, by masking
        /// both with the bit spread across a word.
        static func select(_ bit: UInt64, _ whenSet: [UInt64], _ otherwise: [UInt64]) -> [UInt64] {
            let mask = 0 &- bit
            var selected = [UInt64](repeating: 0, count: limbCount)
            for index in 0..<limbCount {
                selected[index] = (whenSet[index] & mask) | (otherwise[index] & ~mask)
            }
            return selected
        }

        static func isZero(_ value: [UInt64]) -> Bool {
            var folded: UInt64 = 0
            for index in 0..<limbCount { folded |= value[index] }
            return folded == 0
        }

        static func isEqual(_ lhs: [UInt64], _ rhs: [UInt64]) -> Bool {
            var folded: UInt64 = 0
            for index in 0..<limbCount { folded |= lhs[index] ^ rhs[index] }
            return folded == 0
        }

        static func lessThan(_ lhs: [UInt64], _ rhs: [UInt64]) -> Bool {
            subtract(lhs, rhs).borrow == 1
        }

        /// lhs − rhs mod 2²⁵⁶, and 1 when rhs > lhs. Limbs are below 2³², so
        /// a negative limb difference sets the word's top bit.
        static func subtract(_ lhs: [UInt64], _ rhs: [UInt64]) -> (difference: [UInt64], borrow: UInt64) {
            var difference = [UInt64](repeating: 0, count: limbCount)
            var borrow: UInt64 = 0
            for index in 0..<limbCount {
                let word = lhs[index] &- rhs[index] &- borrow
                difference[index] = word & limbMask
                borrow = word >> 63
            }
            return (difference, borrow)
        }

        /// (lhs + rhs) mod n for lhs, rhs < n. The sum is below 2n, so one
        /// subtraction of n reduces it, kept by a mask rather than a branch.
        static func add(_ lhs: [UInt64], _ rhs: [UInt64]) -> [UInt64] {
            var sum = [UInt64](repeating: 0, count: limbCount)
            var carry: UInt64 = 0
            for index in 0..<limbCount {
                let word = lhs[index] &+ rhs[index] &+ carry
                sum[index] = word & limbMask
                carry = word >> 32
            }
            let (reduced, borrow) = subtract(sum, order)
            // The full sum is at least n exactly when it carried out of 256
            // bits or n came off it without a borrow.
            return select(carry | (borrow ^ 1), reduced, sum)
        }

        /// (lhs · rhs) mod n for lhs, rhs < n, by double-and-add over all 256
        /// bits of rhs, each step computing the addition and keeping it by the
        /// bit. Slow, and independent of `montgomeryMultiply`: it checks the
        /// inverse.
        static func multiply(_ lhs: [UInt64], _ rhs: [UInt64]) -> [UInt64] {
            var accumulator = [UInt64](repeating: 0, count: limbCount)
            for bit in stride(from: 255, through: 0, by: -1) {
                accumulator = add(accumulator, accumulator)
                accumulator = select(bitOf(rhs, bit), add(accumulator, lhs), accumulator)
            }
            return accumulator
        }

        /// lhs · rhs · 2⁻²⁵⁶ mod n for lhs, rhs < n: coarsely integrated
        /// operand scanning, one limb of rhs per round, each round adding
        /// lhs times that limb and then a multiple of n that clears the lowest
        /// limb. The total stays below 2n, and one masked subtraction of n
        /// ends it. No word overflows: a limb product is below 2⁶⁴ − 2³³ + 1,
        /// and what is added to it is below 2³³ − 1.
        static func montgomeryMultiply(_ lhs: [UInt64], _ rhs: [UInt64]) -> [UInt64] {
            var total = [UInt64](repeating: 0, count: limbCount + 2)
            for round in 0..<limbCount {
                var carry: UInt64 = 0
                for index in 0..<limbCount {
                    let word = total[index] &+ lhs[index] &* rhs[round] &+ carry
                    total[index] = word & limbMask
                    carry = word >> 32
                }
                var word = total[limbCount] &+ carry
                total[limbCount] = word & limbMask
                total[limbCount + 1] = word >> 32

                let factor = (total[0] &* montgomeryFactor) & limbMask
                word = total[0] &+ factor &* order[0]
                carry = word >> 32
                for index in 1..<limbCount {
                    word = total[index] &+ factor &* order[index] &+ carry
                    total[index - 1] = word & limbMask
                    carry = word >> 32
                }
                word = total[limbCount] &+ carry
                total[limbCount - 1] = word & limbMask
                total[limbCount] = total[limbCount + 1] &+ (word >> 32)
            }
            let low = Array(total[0..<limbCount])
            let (reduced, borrow) = subtract(low, order)
            return select(total[limbCount] | (borrow ^ 1), reduced, low)
        }
    }
}
