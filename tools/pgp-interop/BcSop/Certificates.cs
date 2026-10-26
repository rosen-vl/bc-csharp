using System;
using System.Collections.Generic;

using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Bcpg.Sig;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Tools.PgpInterop
{
    /// <summary>
    /// The validity of certificates and their keys at a point in time (RFC 9580 5.2.3.10, 10.1): only
    /// self-signatures and binding signatures that verify count, the newest one in effect at that time wins, a
    /// version 6 key needs a valid direct-key signature, and revoked or expired keys are not used. Revocations only
    /// count if they verify. Signatures are checked at their creation time, encryption and signing at the current
    /// time.
    /// </summary>
    internal static partial class Program
    {
        /// <summary>
        /// Whether a signature by the key made at the given time counts as a signature of the certificate: the
        /// primary key if it is valid and its newest valid self-signature lets it sign, or a valid subkey whose
        /// newest valid binding signature lets it sign and embeds a valid primary key binding signature
        /// (RFC 9580 5.2.1.8).
        /// </summary>
        private static bool CanSignFor(PgpPublicKeyRing cert, PgpPublicKey key, DateTime at)
        {
            PgpPublicKey primary = cert.GetPublicKey();
            if (!IsValidPrimary(primary, at))
                return false;

            if (Arrays.AreEqual(key.GetFingerprint(), primary.GetFingerprint()))
                return PrimaryAllowsSigning(primary, at);

            PgpSignature binding = NewestValidBinding(primary, key, at);
            return IsValidSubkey(primary, key, binding, at) && HasFlag(binding, PgpKeyFlags.CanSign, ifAbsent: false)
                && HasValidBackSignature(primary, key, binding);
        }

        /// <summary>
        /// Whether the primary key can be used at the given time: it exists, has a valid self-signature (a direct-key
        /// signature for version 6 keys), and is neither revoked nor expired.
        /// </summary>
        private static bool IsValidPrimary(PgpPublicKey primary, DateTime at)
        {
            if (at < primary.CreationTime)
                return false;
            if (primary.Version == PublicKeyPacket.Version6 && NewestValidDirectKeySignature(primary, at) == null)
                return false;
            if (IsRevoked(primary, null, at))
                return false;

            return !IsKeyExpired(primary, NewestValidSelfSignature(primary, at), at);
        }

        /// <summary>
        /// Whether a subkey with the given newest valid binding signature can be used at the given time: it exists,
        /// and is neither revoked nor expired.
        /// </summary>
        private static bool IsValidSubkey(PgpPublicKey primary, PgpPublicKey subkey, PgpSignature binding,
            DateTime at)
        {
            return binding != null && at >= subkey.CreationTime && !IsKeyExpired(subkey, binding, at) &&
                !IsRevoked(primary, subkey, at);
        }

        /// <summary>
        /// Whether the newest valid self-signature lets the primary key sign. Without key flags, the primary key may
        /// sign (older keys).
        /// </summary>
        private static bool PrimaryAllowsSigning(PgpPublicKey primary, DateTime at)
        {
            PgpSignature newest = NewestValidSelfSignature(primary, at);
            return newest == null || HasFlag(newest, PgpKeyFlags.CanSign, ifAbsent: true);
        }

        /// <summary>
        /// The newest valid self-signature with the properties of the primary key: the direct-key signature of a
        /// version 6 key, and of a version 4 key the newest of its direct-key signatures and of the newest valid
        /// certification of each user ID and user attribute that is not revoked.
        /// </summary>
        private static PgpSignature NewestValidSelfSignature(PgpPublicKey primary, DateTime at)
        {
            PgpSignature newest = NewestValidDirectKeySignature(primary, at);
            if (primary.Version == PublicKeyPacket.Version6)
                return newest;

            // the raw user IDs, since the strings of GetUserIds() are not decoded as UTF-8
            foreach (byte[] id in primary.GetRawUserIds())
            {
                PgpSignature current = CurrentSelfCertification(primary, primary.GetSignaturesForId(id), at,
                    signature => VerifiesSelfSignature(signature, primary, id));
                if (current != null && IsNewer(current, newest))
                {
                    newest = current;
                }
            }

            // user attributes have self-signatures like user IDs (RFC 9580 5.12)
            foreach (PgpUserAttributeSubpacketVector attributes in primary.GetUserAttributes())
            {
                PgpSignature current = CurrentSelfCertification(primary,
                    primary.GetSignaturesForUserAttribute(attributes), at,
                    signature => VerifiesAttributeSignature(signature, primary, attributes));
                if (current != null && IsNewer(current, newest))
                {
                    newest = current;
                }
            }
            return newest;
        }

        /// <summary>
        /// The current self-signature of a user ID or user attribute: its newest certification that verifies and is
        /// in effect, or null if there is none or a newer certification revocation retires the user ID. Such a
        /// revocation spares only the non-revocable certifications (RFC 9580 5.2.3.20), the newest of which then
        /// applies, without the properties of the newer certifications that it revokes.
        /// </summary>
        private static PgpSignature CurrentSelfCertification(PgpPublicKey primary,
            IEnumerable<PgpSignature> signatures, DateTime at, Func<PgpSignature, bool> verifies)
        {
            PgpSignature certification = null, revocation = null;
            PgpSignature irrevocable = null;
            foreach (PgpSignature signature in signatures)
            {
                if (!IsSelfCertification(signature, primary) || !IsInEffect(signature, at) || !verifies(signature))
                    continue;

                if (signature.SignatureType == PgpSignature.CertificationRevocation)
                {
                    if (IsNewer(signature, revocation))
                    {
                        revocation = signature;
                    }
                    continue;
                }

                if (IsNewer(signature, certification))
                {
                    certification = signature;
                }
                if (signature.GetHashedSubPackets()?.IsRevocable() == false && IsNewer(signature, irrevocable))
                {
                    irrevocable = signature;
                }
            }

            bool revoked = revocation != null && IsNewer(revocation, certification);
            return revoked ? irrevocable : certification;
        }

        private static PgpSignature NewestValidDirectKeySignature(PgpPublicKey primary, DateTime at)
        {
            PgpSignature newest = null;
            foreach (PgpSignature signature in primary.GetSignaturesOfType(PgpSignature.DirectKey))
            {
                if (signature.KeyId == primary.KeyId && IsNewer(signature, newest) && IsInEffect(signature, at) &&
                    VerifiesSelfSignature(signature, primary, null))
                {
                    newest = signature;
                }
            }
            return newest;
        }

        /// <summary>The newest subkey binding signature that verifies decides about the subkey.</summary>
        private static PgpSignature NewestValidBinding(PgpPublicKey primary, PgpPublicKey subkey, DateTime at)
        {
            PgpSignature newest = null;
            foreach (PgpSignature binding in subkey.GetSignaturesOfType(PgpSignature.SubkeyBinding))
            {
                if (IsNewer(binding, newest) && IsInEffect(binding, at) && VerifiesBinding(binding, primary, subkey))
                {
                    newest = binding;
                }
            }
            return newest;
        }

        /// <summary>
        /// Whether the primary key (subkey null) or the subkey is revoked at the given time (RFC 9580 5.2.3.31): a
        /// revocation that verifies counts at all times if it is hard, and from its creation on if it is soft (the key
        /// is superseded or retired, or the user ID no longer valid). An expired revocation does not count.
        /// </summary>
        private static bool IsRevoked(PgpPublicKey primary, PgpPublicKey subkey, DateTime at)
        {
            IEnumerable<PgpSignature> revocations = subkey == null
                ? primary.GetSignaturesOfType(PgpSignature.KeyRevocation)
                : subkey.GetSignaturesOfType(PgpSignature.SubkeyRevocation);
            foreach (PgpSignature revocation in revocations)
            {
                if ((!IsHardRevocation(revocation) && revocation.CreationTime > at) || IsExpired(revocation, at))
                    continue;

                if (subkey == null
                    ? VerifiesSelfSignature(revocation, primary, null)
                    : VerifiesBinding(revocation, primary, subkey))
                {
                    return true;
                }
            }
            return false;
        }

        private static bool IsHardRevocation(PgpSignature revocation)
        {
            RevocationReason reason = revocation.GetHashedSubPackets()?.GetRevocationReason();
            if (reason == null)
                return true;

            switch (reason.GetRevocationReason())
            {
            case RevocationReasonTag.KeySuperseded:
            case RevocationReasonTag.KeyRetired:
            case RevocationReasonTag.UserNoLongerValid:
                return false;
            default:
                return true;
            }
        }

        /// <summary>A direct-key signature or revocation (no user ID), or a signature over a user ID.</summary>
        private static bool VerifiesSelfSignature(PgpSignature signature, PgpPublicKey primary, byte[] userId)
        {
            try
            {
                signature.InitVerify(primary);
                return userId == null
                    ? signature.VerifyCertification(primary)
                    : signature.VerifyCertification(userId, primary);
            }
            catch (Exception e) when (e is PgpException || e is InvalidOperationException)
            {
                return false;
            }
        }

        private static bool VerifiesAttributeSignature(PgpSignature signature, PgpPublicKey primary,
            PgpUserAttributeSubpacketVector attributes)
        {
            try
            {
                signature.InitVerify(primary);
                return signature.VerifyCertification(attributes, primary);
            }
            catch (Exception e) when (e is PgpException || e is InvalidOperationException)
            {
                return false;
            }
        }

        /// <summary>A certification of a user ID or user attribute by the primary key, or its revocation.</summary>
        private static bool IsSelfCertification(PgpSignature signature, PgpPublicKey primary)
        {
            int type = signature.SignatureType;
            return signature.KeyId == primary.KeyId && (type == PgpSignature.CertificationRevocation ||
                (type >= PgpSignature.DefaultCertification && type <= PgpSignature.PositiveCertification));
        }

        /// <summary>A subkey binding signature or revocation.</summary>
        private static bool VerifiesBinding(PgpSignature signature, PgpPublicKey primary, PgpPublicKey subkey)
        {
            try
            {
                signature.InitVerify(primary);
                return signature.VerifyCertification(primary, subkey);
            }
            catch (Exception e) when (e is PgpException || e is InvalidOperationException)
            {
                return false;
            }
        }

        private static bool IsNewer(PgpSignature signature, PgpSignature than) =>
            than == null || signature.CreationTime > than.CreationTime;

        /// <summary>Whether a self-signature or binding signature is made by then, and not expired.</summary>
        private static bool IsInEffect(PgpSignature signature, DateTime at) =>
            signature.CreationTime <= at && !IsExpired(signature, at);

        /// <summary>Whether the signature has expired by the given time (RFC 9580 5.2.3.18).</summary>
        private static bool IsExpired(PgpSignature signature, DateTime at)
        {
            long seconds = signature.GetHashedSubPackets()?.GetSignatureExpirationTime() ?? 0;
            return seconds > 0 && signature.CreationTime.AddSeconds(seconds) <= at;
        }

        /// <summary>
        /// Whether the key has expired by the given time, by the key expiration time of its self-signature or binding
        /// signature in effect (RFC 9580 5.2.3.13). Without one, the key does not expire.
        /// </summary>
        private static bool IsKeyExpired(PgpPublicKey key, PgpSignature signature, DateTime at)
        {
            long seconds = signature?.GetHashedSubPackets()?.GetKeyExpirationTime() ?? 0;
            return seconds > 0 && key.CreationTime.AddSeconds(seconds) <= at;
        }

        /// <summary>A signature over a document that has not expired (RFC 9580 5.2.3.18).</summary>
        private static bool IsValidDocumentSignature(PgpSignature signature) =>
            IsDocumentSignature(signature) && !IsExpired(signature, DateTime.UtcNow);

        /// <summary>Only binary and text signatures are signatures over documents (RFC 9580 5.2.1.1-2).</summary>
        private static bool IsDocumentSignature(PgpSignature signature) =>
            signature.SignatureType == PgpSignature.BinaryDocument ||
            signature.SignatureType == PgpSignature.CanonicalTextDocument;
    }
}
