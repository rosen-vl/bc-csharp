using System;
using System.IO;
using System.Text;

using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.Attr;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Bcpg.Sig;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Tools.PgpInterop.Fixtures
{
    /// <summary>
    /// Makes the certificates and signatures of the bcsop tests of certificate validity that a shell script cannot
    /// make: forged and genuine self-signatures, binding signatures of a subkey that change its flags, a signature
    /// over the message of a type that is not a document type, and revocations, expiries and signatures at given
    /// times. The message is "Hello\n". The keys are random, so each run makes other files; run-bcsop-tests.sh uses
    /// the ones in this directory.
    /// </summary>
    /// <remarks>
    /// Usage: dotnet run --project tools/pgp-interop/fixtures/MakeFixtures -- tools/pgp-interop/fixtures
    /// </remarks>
    internal static class Program
    {
        private static readonly SecureRandom Random = new SecureRandom();
        private static readonly byte[] Message = Encoding.UTF8.GetBytes("Hello\n");
        private static readonly DateTime Start = DateTime.UtcNow.AddDays(-2);

        private static int Main(string[] args)
        {
            string directory = args.Length > 0 ? args[0] : ".";

            // the newest valid self-signature decides about the flags of the primary key; a forged newer one,
            // which does not verify, does not let a certification-only primary key sign
            PgpKeyPair certifier = Ed25519Pair(Start);
            PgpPublicKey certifyOnly = AddCertification(certifier.PublicKey,
                DirectKeySignature(certifier, Start.AddHours(1), PgpKeyFlags.CanCertify));
            Write(directory, "forged-flags.pub", Ring(AddCertification(certifyOnly,
                ForgedDirectKeySignature(certifier, Start.AddHours(2), PgpKeyFlags.CanCertify | PgpKeyFlags.CanSign))));
            Write(directory, "granted-flags.pub", Ring(AddCertification(certifyOnly,
                DirectKeySignature(certifier, Start.AddHours(2), PgpKeyFlags.CanCertify | PgpKeyFlags.CanSign))));
            Write(directory, "primary.sig", DocumentSignature(certifier, PgpSignature.BinaryDocument));

            // the newest valid binding signature decides about a subkey
            PgpKeyPair primary = Ed25519Pair(Start);
            PgpPublicKey primaryKey = AddCertification(primary.PublicKey,
                DirectKeySignature(primary, Start.AddHours(1), PgpKeyFlags.CanCertify));
            PgpKeyPair signer = Ed25519Pair(Start);
            Write(directory, "signing-revoked.pub", Ring(primaryKey, Subkey(primary, signer,
                Binding(primary, primaryKey, signer, Start.AddHours(1), PgpKeyFlags.CanSign),
                Binding(primary, primaryKey, signer, Start.AddHours(2), PgpKeyFlags.CanCertify))));
            Write(directory, "signing-granted.pub", Ring(primaryKey, Subkey(primary, signer,
                Binding(primary, primaryKey, signer, Start.AddHours(1), PgpKeyFlags.CanCertify),
                Binding(primary, primaryKey, signer, Start.AddHours(2), PgpKeyFlags.CanSign))));
            Write(directory, "subkey.sig", DocumentSignature(signer, PgpSignature.BinaryDocument));

            PgpKeyPair encryption = X25519Pair(Start);
            int encrypt = PgpKeyFlags.CanEncryptCommunications | PgpKeyFlags.CanEncryptStorage;
            Write(directory, "encryption-revoked.pub", Ring(primaryKey, Subkey(primary, encryption,
                Binding(primary, primaryKey, encryption, Start.AddHours(1), encrypt),
                Binding(primary, primaryKey, encryption, Start.AddHours(2), PgpKeyFlags.CanCertify))));

            // only binary and text signatures are signatures over documents
            PgpKeyPair documentSigner = Ed25519Pair(Start);
            Write(directory, "document-signer.pub", Ring(AddCertification(documentSigner.PublicKey,
                DirectKeySignature(documentSigner, Start.AddHours(1), PgpKeyFlags.CanCertify | PgpKeyFlags.CanSign))));
            Write(directory, "binary.sig", DocumentSignature(documentSigner, PgpSignature.BinaryDocument));
            Write(directory, "direct-key-type.sig", DocumentSignature(documentSigner, PgpSignature.DirectKey));

            // a signature counts if the key signs for the certificate when the signature is made: after the key is
            // made, before it expires, and before a soft revocation or while an expiring revocation is not in effect
            PgpKeyPair timed = Ed25519Pair(Start);
            PgpPublicKey timedKey = AddCertification(timed.PublicKey,
                DirectKeySignature(timed, Start, PgpKeyFlags.CanCertify | PgpKeyFlags.CanSign));
            Write(directory, "timed.pub", Ring(timedKey));
            Write(directory, "timed-soft-revoked.pub", Ring(AddCertification(timedKey,
                Revocation(timed, Start.AddHours(3), RevocationReasonTag.KeyRetired, 0))));
            Write(directory, "timed-hard-revoked.pub", Ring(AddCertification(timedKey,
                Revocation(timed, Start.AddHours(3), RevocationReasonTag.KeyCompromised, 0))));
            Write(directory, "timed-suspended.pub", Ring(AddCertification(timedKey,
                Revocation(timed, Start.AddHours(3), RevocationReasonTag.KeyRetired, 3600))));
            Write(directory, "timed-expired.pub", Ring(AddCertification(timedKey, DirectKeySignature(timed,
                Start.AddHours(1), PgpKeyFlags.CanCertify | PgpKeyFlags.CanSign, keyExpiry: 4 * 3600))));
            Write(directory, "timed-early.sig", DocumentSignature(timed, PgpSignature.BinaryDocument,
                Start.AddHours(-1)));
            Write(directory, "timed-before.sig", DocumentSignature(timed, PgpSignature.BinaryDocument,
                Start.AddHours(2)));
            Write(directory, "timed-during.sig", DocumentSignature(timed, PgpSignature.BinaryDocument,
                Start.AddHours(3.5)));
            Write(directory, "timed-after.sig", DocumentSignature(timed, PgpSignature.BinaryDocument,
                Start.AddHours(5)));

            // a malformed embedded signature in the unhashed area does not spoil the valid back-signature
            PgpKeyPair embeddingPrimary = Ed25519Pair(Start);
            PgpPublicKey embeddingPrimaryKey = AddCertification(embeddingPrimary.PublicKey,
                DirectKeySignature(embeddingPrimary, Start.AddHours(1), PgpKeyFlags.CanCertify));
            PgpKeyPair embeddingSigner = Ed25519Pair(Start);
            var malformed = new PgpSignatureSubpacketGenerator();
            malformed.AddCustomSubpacket(new EmbeddedSignature(false, false, new byte[]{ 4, 0x19, 0 }));
            Write(directory, "malformed-embedded.pub", Ring(embeddingPrimaryKey, Subkey(embeddingPrimary,
                embeddingSigner, Binding(embeddingPrimary, embeddingPrimaryKey, embeddingSigner, Start.AddHours(1),
                PgpKeyFlags.CanSign, malformed.Generate()))));
            Write(directory, "malformed-embedded.sig", DocumentSignature(embeddingSigner,
                PgpSignature.BinaryDocument));

            // a back-signature with an octet after its signature value is malformed (RFC 9580 5.2.3), and does
            // not let the subkey sign
            PgpKeyPair trailingSigner = Ed25519Pair(Start);
            Write(directory, "trailing-back-signature.pub", Ring(embeddingPrimaryKey, Subkey(embeddingPrimary,
                trailingSigner, BindingWithTrailingBackSignature(embeddingPrimary, embeddingPrimaryKey,
                trailingSigner, Start.AddHours(1)))));
            Write(directory, "trailing-back-signature.sig", DocumentSignature(trailingSigner,
                PgpSignature.BinaryDocument));

            // the self-signature of a user attribute decides about the flags of a version 4 primary key
            PgpKeyPair attributed = Ed25519Pair(Start, version: 4);
            var attributesGenerator = new PgpUserAttributeSubpacketVectorGenerator();
            attributesGenerator.SetImageAttribute(ImageAttrib.Format.Jpeg, new byte[]{ 0xFF, 0xD8, 0xFF, 0xD9 });
            PgpUserAttributeSubpacketVector attributes = attributesGenerator.Generate();
            Write(directory, "attribute-certify-only.pub", Ring(PgpPublicKey.AddCertification(attributed.PublicKey,
                attributes, AttributeCertification(attributed, attributes, PgpKeyFlags.CanCertify))));
            Write(directory, "attribute-signs.pub", Ring(PgpPublicKey.AddCertification(attributed.PublicKey,
                attributes, AttributeCertification(attributed, attributes,
                    PgpKeyFlags.CanCertify | PgpKeyFlags.CanSign))));
            Write(directory, "attribute.sig", DocumentSignature(attributed, PgpSignature.BinaryDocument));

            // a non-revocable certify-only self-signature of a user ID ignores a later revocation of the user ID
            PgpKeyPair certified = Ed25519Pair(Start, version: 4);
            foreach (bool revocable in new[]{ false, true })
            {
                PgpPublicKey key = PgpPublicKey.AddCertification(certified.PublicKey, "id",
                    UserIdCertification(certified, PgpSignature.PositiveCertification, Start.AddHours(1), revocable));
                key = PgpPublicKey.AddCertification(key, "id",
                    UserIdCertification(certified, PgpSignature.CertificationRevocation, Start.AddHours(2), true));
                Write(directory, revocable ? "uid-revocable.pub" : "uid-irrevocable.pub", Ring(key));
            }

            // but it does not spare a newer revocable self-signature that lets the key sign
            PgpPublicKey superseded = PgpPublicKey.AddCertification(certified.PublicKey, "id",
                UserIdCertification(certified, PgpSignature.PositiveCertification, Start.AddHours(1), false));
            superseded = PgpPublicKey.AddCertification(superseded, "id", UserIdCertification(certified,
                PgpSignature.PositiveCertification, Start.AddHours(1.5), true, PgpKeyFlags.CanSign));
            superseded = PgpPublicKey.AddCertification(superseded, "id",
                UserIdCertification(certified, PgpSignature.CertificationRevocation, Start.AddHours(2), true));
            Write(directory, "uid-superseded.pub", Ring(superseded));
            Write(directory, "uid.sig", DocumentSignature(certified, PgpSignature.BinaryDocument));

            // an expired signature, and one with an intended recipient outside an encrypted message, do not count
            PgpKeyPair contextSigner = Ed25519Pair(Start);
            Write(directory, "context-signer.pub", Ring(AddCertification(contextSigner.PublicKey,
                DirectKeySignature(contextSigner, Start.AddHours(1), PgpKeyFlags.CanCertify | PgpKeyFlags.CanSign))));
            var expiring = new PgpSignatureSubpacketGenerator();
            expiring.SetSignatureCreationTime(false, Start.AddHours(2));
            expiring.SetSignatureExpirationTime(false, 3600);
            Write(directory, "expired.sig", DocumentSignature(contextSigner, PgpSignature.BinaryDocument,
                hashed: expiring.Generate()));
            var addressed = new PgpSignatureSubpacketGenerator();
            addressed.SetSignatureCreationTime(false, Start.AddHours(2));
            addressed.AddIntendedRecipientFingerprint(false, contextSigner.PublicKey);
            Write(directory, "intended-recipient.sig", DocumentSignature(contextSigner, PgpSignature.BinaryDocument,
                hashed: addressed.Generate()));
            Write(directory, "context.sig", DocumentSignature(contextSigner, PgpSignature.BinaryDocument,
                Start.AddHours(2)));
            return 0;
        }

        private static PgpKeyPair Ed25519Pair(DateTime time, int version = 6)
        {
            var generator = new Ed25519KeyPairGenerator();
            generator.Init(new Ed25519KeyGenerationParameters(Random));
            return new PgpKeyPair(version, PublicKeyAlgorithmTag.Ed25519, generator.GenerateKeyPair(), time);
        }

        private static PgpKeyPair X25519Pair(DateTime time)
        {
            var generator = new X25519KeyPairGenerator();
            generator.Init(new X25519KeyGenerationParameters(Random));
            return new PgpKeyPair(6, PublicKeyAlgorithmTag.X25519, generator.GenerateKeyPair(), time);
        }

        private static PgpSignatureSubpacketVector Hashed(DateTime time, int flags, PgpSignature embedded = null,
            long keyExpiry = 0)
        {
            var hashed = new PgpSignatureSubpacketGenerator();
            hashed.SetSignatureCreationTime(false, time);
            hashed.SetKeyFlags(false, flags);
            if (keyExpiry > 0)
            {
                hashed.SetKeyExpirationTime(false, keyExpiry);
            }
            if (embedded != null)
            {
                hashed.AddEmbeddedSignature(false, embedded);
            }
            return hashed.Generate();
        }

        private static PgpSignature DirectKeySignature(PgpKeyPair key, DateTime time, int flags, long keyExpiry = 0)
        {
            var generator = new PgpSignatureGenerator(key.PublicKey.Algorithm, HashAlgorithmTag.Sha256);
            generator.InitSign(PgpSignature.DirectKey, key.PrivateKey, Random);
            generator.SetHashedSubpackets(Hashed(time, flags, keyExpiry: keyExpiry));
            return generator.GenerateCertification(key.PublicKey);
        }

        private static PgpSignature AttributeCertification(PgpKeyPair key, PgpUserAttributeSubpacketVector attributes,
            int flags)
        {
            var generator = new PgpSignatureGenerator(key.PublicKey.Algorithm, HashAlgorithmTag.Sha256);
            generator.InitSign(PgpSignature.PositiveCertification, key.PrivateKey, Random);
            generator.SetHashedSubpackets(Hashed(Start.AddHours(1), flags));
            return generator.GenerateCertification(attributes, key.PublicKey);
        }

        /// <summary>A certification of the user ID "id" that lets the key certify, or its revocation.</summary>
        private static PgpSignature UserIdCertification(PgpKeyPair key, int type, DateTime time, bool revocable,
            int moreFlags = 0)
        {
            var hashed = new PgpSignatureSubpacketGenerator();
            hashed.SetSignatureCreationTime(false, time);
            if (type != PgpSignature.CertificationRevocation)
            {
                hashed.SetKeyFlags(false, PgpKeyFlags.CanCertify | moreFlags);
                hashed.SetRevocable(false, revocable);
            }
            var generator = new PgpSignatureGenerator(key.PublicKey.Algorithm, HashAlgorithmTag.Sha256);
            generator.InitSign(type, key.PrivateKey, Random);
            generator.SetHashedSubpackets(hashed.Generate());
            return generator.GenerateCertification("id", key.PublicKey);
        }

        /// <summary>A key revocation with the given reason, which expires after the given seconds unless 0.</summary>
        private static PgpSignature Revocation(PgpKeyPair key, DateTime time, RevocationReasonTag reason,
            long validSeconds)
        {
            var hashed = new PgpSignatureSubpacketGenerator();
            hashed.SetSignatureCreationTime(false, time);
            hashed.SetRevocationReason(false, reason, "");
            if (validSeconds > 0)
            {
                hashed.SetSignatureExpirationTime(false, validSeconds);
            }
            var generator = new PgpSignatureGenerator(key.PublicKey.Algorithm, HashAlgorithmTag.Sha256);
            generator.InitSign(PgpSignature.KeyRevocation, key.PrivateKey, Random);
            generator.SetHashedSubpackets(hashed.Generate());
            return generator.GenerateCertification(key.PublicKey);
        }

        /// <summary>A direct-key signature with a signature value of zeroes, which does not verify.</summary>
        private static PgpSignature ForgedDirectKeySignature(PgpKeyPair key, DateTime time, int flags)
        {
            var packet = new SignaturePacket(6, true, PgpSignature.DirectKey, key.KeyId, key.PublicKey.Algorithm,
                HashAlgorithmTag.Sha256, new SignatureSubpacket[]
                {
                    new SignatureCreationTime(false, time),
                    new IssuerFingerprint(false, 6, key.PublicKey.GetFingerprint()),
                    new KeyFlags(false, flags),
                }, new SignatureSubpacket[0], new byte[2], SecureRandom.GetNextBytes(Random, 16), null, new byte[64]);
            return ((PgpSignatureList)new PgpObjectFactory(packet.GetEncoded()).NextPgpObject())[0];
        }

        /// <summary>
        /// A subkey binding signature with the given flags, which embeds a primary key binding signature if the
        /// subkey signs.
        /// </summary>
        private static PgpSignature Binding(PgpKeyPair primary, PgpPublicKey primaryKey, PgpKeyPair subkey,
            DateTime time, int flags, PgpSignatureSubpacketVector unhashed = null)
        {
            PgpPublicKey subkeyKey = SubkeyKey(subkey);
            PgpSignature embedded = null;
            if ((flags & PgpKeyFlags.CanSign) != 0)
            {
                var back = new PgpSignatureGenerator(subkey.PublicKey.Algorithm, HashAlgorithmTag.Sha256);
                back.InitSign(PgpSignature.PrimaryKeyBinding, subkey.PrivateKey, Random);
                var backHashed = new PgpSignatureSubpacketGenerator();
                backHashed.SetSignatureCreationTime(false, time);
                back.SetHashedSubpackets(backHashed.Generate());
                embedded = back.GenerateCertification(primaryKey, subkeyKey);
            }

            var generator = new PgpSignatureGenerator(primary.PublicKey.Algorithm, HashAlgorithmTag.Sha256);
            generator.InitSign(PgpSignature.SubkeyBinding, primary.PrivateKey, Random);
            generator.SetHashedSubpackets(Hashed(time, flags, embedded));
            if (unhashed != null)
            {
                generator.SetUnhashedSubpackets(unhashed);
            }
            return generator.GenerateCertification(primaryKey, subkeyKey);
        }

        /// <summary>A binding of a signing subkey with its back-signature, and an extra octet at its end.</summary>
        private static PgpSignature BindingWithTrailingBackSignature(PgpKeyPair primary, PgpPublicKey primaryKey,
            PgpKeyPair subkey, DateTime time)
        {
            PgpPublicKey subkeyKey = SubkeyKey(subkey);
            var back = new PgpSignatureGenerator(subkey.PublicKey.Algorithm, HashAlgorithmTag.Sha256);
            back.InitSign(PgpSignature.PrimaryKeyBinding, subkey.PrivateKey, Random);
            var backHashed = new PgpSignatureSubpacketGenerator();
            backHashed.SetSignatureCreationTime(false, time);
            back.SetHashedSubpackets(backHashed.Generate());
            byte[] packet = back.GenerateCertification(primaryKey, subkeyKey).GetEncoded();

            // the body of the new-format packet, with a one-octet length, and one octet more
            byte[] body = new byte[packet.Length - 2 + 1];
            Array.Copy(packet, 2, body, 0, packet.Length - 2);
            body[body.Length - 1] = 0x42;

            var hashed = new PgpSignatureSubpacketGenerator();
            hashed.SetSignatureCreationTime(false, time);
            hashed.SetKeyFlags(false, PgpKeyFlags.CanSign);
            hashed.AddCustomSubpacket(new EmbeddedSignature(false, false, body));
            var generator = new PgpSignatureGenerator(primary.PublicKey.Algorithm, HashAlgorithmTag.Sha256);
            generator.InitSign(PgpSignature.SubkeyBinding, primary.PrivateKey, Random);
            generator.SetHashedSubpackets(hashed.Generate());
            return generator.GenerateCertification(primaryKey, subkeyKey);
        }

        private static PgpPublicKey SubkeyKey(PgpKeyPair subkey) => new PgpPublicKey(new PublicSubkeyPacket(6,
            subkey.PublicKey.Algorithm, subkey.PublicKey.CreationTime, subkey.PublicKey.PublicKeyPacket.Key));

        private static PgpPublicKey Subkey(PgpKeyPair primary, PgpKeyPair subkey, params PgpSignature[] bindings)
        {
            PgpPublicKey key = SubkeyKey(subkey);
            foreach (PgpSignature binding in bindings)
            {
                key = PgpPublicKey.AddCertification(key, binding);
            }
            return key;
        }

        private static PgpPublicKey AddCertification(PgpPublicKey key, PgpSignature signature) =>
            PgpPublicKey.AddCertification(key, signature);

        private static byte[] DocumentSignature(PgpKeyPair key, int type, DateTime? time = null,
            PgpSignatureSubpacketVector hashed = null)
        {
            var generator = new PgpSignatureGenerator(key.PublicKey.Algorithm, HashAlgorithmTag.Sha256);
            generator.InitSign(type, key.PrivateKey, Random);
            if (time != null)
            {
                var timed = new PgpSignatureSubpacketGenerator();
                timed.SetSignatureCreationTime(false, time.Value);
                hashed = timed.Generate();
            }
            if (hashed != null)
            {
                generator.SetHashedSubpackets(hashed);
            }
            generator.Update(Message);
            return generator.Generate().GetEncoded();
        }

        private static byte[] Ring(params PgpPublicKey[] keys)
        {
            var output = new MemoryStream();
            foreach (PgpPublicKey key in keys)
            {
                key.Encode(output);
            }
            return new PgpPublicKeyRing(output.ToArray()).GetEncoded();
        }

        private static void Write(string directory, string name, byte[] data)
        {
            using (var file = File.Create(Path.Combine(directory, name)))
            using (var armored = new ArmoredOutputStream(file, addVersionHeader: false))
            {
                armored.Write(data, 0, data.Length);
            }
        }
    }
}
