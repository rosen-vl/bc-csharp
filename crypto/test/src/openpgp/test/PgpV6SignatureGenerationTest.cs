using System;
using System.IO;
using System.Linq;
using System.Text;

using NUnit.Framework;

using Org.BouncyCastle.Bcpg.Sig;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Bcpg.OpenPgp.Tests
{
    /// <summary>Tests for the generation of version 6 signatures and one-pass signatures (RFC 9580 5.2, 5.4).</summary>
    [TestFixture]
    public class PgpV6SignatureGenerationTest
    {
        private static readonly SecureRandom Random = new SecureRandom();

        private static readonly byte[] Data = Strings.ToUtf8ByteArray("a message to be signed");

        // The version 6 Ed25519 key of RFC 9580 A.4 (unprotected), with an X25519 subkey
        private static PgpSecretKeyRing SecretRing() =>
            new PgpSecretKeyRing(PgpV6TestUtilities.LoadRfc9580("a4-v6-secret-key.asc"));

        private static PgpPublicKey Primary() => SecretRing().GetPublicKey();

        private static PgpPrivateKey PrimaryPrivate() => SecretRing().GetSecretKey().ExtractPrivateKey(new char[0]);

        private static readonly HashAlgorithmTag[] SaltedHashes =
        {
            HashAlgorithmTag.Sha224, HashAlgorithmTag.Sha256, HashAlgorithmTag.Sha384, HashAlgorithmTag.Sha512,
            HashAlgorithmTag.Sha3_256, HashAlgorithmTag.Sha3_512,
        };

        private static PgpSignatureGenerator InitSign(HashAlgorithmTag hash, int type, SecureRandom random = null)
        {
            var generator = new PgpSignatureGenerator(PublicKeyAlgorithmTag.Ed25519, hash);
            generator.InitSign(type, PrimaryPrivate(), random);
            return generator;
        }

        private static bool Verify(PgpSignature signature, byte[] data)
        {
            signature.InitVerify(Primary());
            signature.Update(data);
            return signature.Verify();
        }

        private static PgpSignature Reparse(PgpSignature signature) =>
            ((PgpSignatureList)new PgpObjectFactory(signature.GetEncoded()).NextPgpObject())[0];

        [Test]
        public void BinarySignaturesWithAllSaltedHashes()
        {
            foreach (var hash in SaltedHashes)
            {
                // Ed25519 needs a digest of at least 256 bits
                if (hash == HashAlgorithmTag.Sha224)
                {
                    var weak = new PgpSignatureGenerator(PublicKeyAlgorithmTag.Ed25519, hash);
                    Assert.Throws<PgpException>(() => weak.InitSign(PgpSignature.BinaryDocument, PrimaryPrivate()));
                    continue;
                }

                PgpSignatureGenerator generator = InitSign(hash, PgpSignature.BinaryDocument);
                generator.Update(Data);
                PgpSignature signature = generator.Generate();

                Assert.That(signature.Version, Is.EqualTo(6), hash.ToString());
                Assert.That(signature.GetSalt().Length, Is.EqualTo(PgpUtilities.GetV6SaltSize(hash)));
                Assert.That(signature.KeyId, Is.EqualTo(Primary().KeyId));

                PgpSignature parsed = Reparse(signature);
                Assert.That(parsed.Version, Is.EqualTo(6));
                Assert.That(Verify(parsed, Data), Is.True, hash.ToString());
                Assert.That(Verify(parsed, Strings.ToUtf8ByteArray("other")), Is.False);
            }
        }

        /// <summary>Hashes without a salt size cannot be used for version 6 signatures.</summary>
        [Test]
        public void HashesWithoutSaltSizeAreRefused()
        {
            foreach (var hash in new[]{ HashAlgorithmTag.Sha1, HashAlgorithmTag.MD5, HashAlgorithmTag.RipeMD160 })
            {
                var generator = new PgpSignatureGenerator(PublicKeyAlgorithmTag.Ed25519, hash);
                Assert.Throws<PgpException>(() => generator.InitSign(PgpSignature.BinaryDocument, PrimaryPrivate()),
                    hash.ToString());
            }
        }

        [Test]
        public void TextSignatureCanonicalisesLineEndings()
        {
            PgpSignatureGenerator generator = InitSign(HashAlgorithmTag.Sha512, PgpSignature.CanonicalTextDocument);
            generator.Update(Strings.ToUtf8ByteArray("first\nsecond\r\nthird\r"));
            PgpSignature signature = Reparse(generator.Generate());

            Assert.That(Verify(signature, Strings.ToUtf8ByteArray("first\r\nsecond\r\nthird\r\n")), Is.True);
            Assert.That(Verify(signature, Strings.ToUtf8ByteArray("first\nsecond\nthird\n")), Is.True);
            Assert.That(Verify(signature, Strings.ToUtf8ByteArray("first second third")), Is.False);
        }

        [Test]
        public void StandaloneSignature()
        {
            PgpSignatureGenerator generator = InitSign(HashAlgorithmTag.Sha256, PgpSignature.StandAlone);
            PgpSignature signature = Reparse(generator.Generate());

            Assert.That(signature.SignatureType, Is.EqualTo(PgpSignature.StandAlone));
            Assert.That(Verify(signature, new byte[0]), Is.True);
        }

        [Test]
        public void KeySignatures()
        {
            PgpSecretKeyRing ring = SecretRing();
            PgpPublicKey primary = ring.GetPublicKey();
            PgpPublicKey subkey = ring.GetPublicKeys().Last();

            // user ID certification
            PgpSignatureGenerator generator = InitSign(HashAlgorithmTag.Sha512, PgpSignature.PositiveCertification);
            PgpSignature certification = Reparse(generator.GenerateCertification("Test <test@example.org>", primary));
            certification.InitVerify(primary);
            Assert.That(certification.VerifyCertification("Test <test@example.org>", primary), Is.True);
            certification.InitVerify(primary);
            Assert.That(certification.VerifyCertification("Other <other@example.org>", primary), Is.False);

            // direct key signature
            generator = InitSign(HashAlgorithmTag.Sha512, PgpSignature.DirectKey);
            PgpSignature direct = Reparse(generator.GenerateCertification(primary));
            direct.InitVerify(primary);
            Assert.That(direct.VerifyCertification(primary), Is.True);

            // subkey binding signature
            generator = InitSign(HashAlgorithmTag.Sha512, PgpSignature.SubkeyBinding);
            PgpSignature binding = Reparse(generator.GenerateCertification(primary, subkey));
            binding.InitVerify(primary);
            Assert.That(binding.VerifyCertification(primary, subkey), Is.True);

            // revocations
            generator = InitSign(HashAlgorithmTag.Sha512, PgpSignature.KeyRevocation);
            PgpSignature keyRevocation = Reparse(generator.GenerateCertification(primary));
            keyRevocation.InitVerify(primary);
            Assert.That(keyRevocation.VerifyCertification(primary), Is.True);

            generator = InitSign(HashAlgorithmTag.Sha512, PgpSignature.SubkeyRevocation);
            PgpSignature subkeyRevocation = Reparse(generator.GenerateCertification(subkey));
            subkeyRevocation.InitVerify(primary);
            Assert.That(subkeyRevocation.VerifyCertification(subkey), Is.True);
        }

        [Test]
        public void IssuerFingerprintIsAddedAndKeyIdIsNot()
        {
            PgpPublicKey primary = Primary();
            PgpSignatureGenerator generator = InitSign(HashAlgorithmTag.Sha256, PgpSignature.BinaryDocument);
            generator.Update(Data);
            PgpSignature signature = Reparse(generator.Generate());

            var hashed = signature.GetHashedSubPackets();
            IssuerFingerprint fingerprint = hashed.GetIssuerFingerprint();
            Assert.That(fingerprint, Is.Not.Null);
            Assert.That(fingerprint.KeyVersion, Is.EqualTo(6));
            Assert.That(fingerprint.GetFingerprint(), Is.EqualTo(primary.GetFingerprint()));
            Assert.That(hashed.HasSubpacket(SignatureSubpacketTag.CreationTime), Is.True);

            Assert.That(hashed.HasSubpacket(SignatureSubpacketTag.IssuerKeyId), Is.False);
            Assert.That(signature.GetUnhashedSubPackets().HasSubpacket(SignatureSubpacketTag.IssuerKeyId), Is.False);
            Assert.That(signature.KeyId, Is.EqualTo(primary.KeyId));

            // a fingerprint supplied by the caller is kept
            var subpackets = new PgpSignatureSubpacketGenerator();
            subpackets.SetIssuerFingerprint(true, primary);
            generator = InitSign(HashAlgorithmTag.Sha256, PgpSignature.BinaryDocument);
            generator.SetHashedSubpackets(subpackets.Generate());
            generator.Update(Data);
            signature = Reparse(generator.Generate());
            Assert.That(signature.GetHashedSubPackets().GetSubpackets(SignatureSubpacketTag.IssuerFingerprint).Length,
                Is.EqualTo(1));
        }

        [Test]
        public void SaltsAreFresh()
        {
            var salts = new System.Collections.Generic.HashSet<string>();
            for (int i = 0; i < 20; ++i)
            {
                PgpSignatureGenerator generator = InitSign(HashAlgorithmTag.Sha512, PgpSignature.BinaryDocument);
                generator.Update(Data);
                PgpSignature signature = generator.Generate();

                salts.Add(Convert.ToBase64String(signature.GetSalt()));
            }
            Assert.That(salts.Count, Is.EqualTo(20));
        }

        [Test]
        public void GeneratorMustBeInitialisedAgain()
        {
            PgpSignatureGenerator generator = InitSign(HashAlgorithmTag.Sha512, PgpSignature.BinaryDocument);
            generator.Update(Data);
            generator.Generate();

            Assert.Throws<InvalidOperationException>(() => generator.Update(Data));
            Assert.Throws<InvalidOperationException>(() => generator.Update((byte)1));
            Assert.Throws<InvalidOperationException>(() => generator.Generate());

            generator.InitSign(PgpSignature.BinaryDocument, PrimaryPrivate());
            generator.Update(Data);
            Assert.That(Verify(Reparse(generator.Generate()), Data), Is.True);
        }

        [Test]
        public void EmptyAndLargeData()
        {
            PgpSignatureGenerator generator = InitSign(HashAlgorithmTag.Sha256, PgpSignature.BinaryDocument);
            Assert.That(Verify(Reparse(generator.Generate()), new byte[0]), Is.True);

            byte[] large = new byte[10 * 1024 * 1024];
            Random.NextBytes(large);
            generator = InitSign(HashAlgorithmTag.Sha512, PgpSignature.BinaryDocument);
            generator.Update(large);
            PgpSignature signature = Reparse(generator.Generate());
            Assert.That(Verify(signature, large), Is.True);
        }

        [Test]
        public void ReservedSignatureTypeIsRefused()
        {
            var generator = new PgpSignatureGenerator(PublicKeyAlgorithmTag.Ed25519, HashAlgorithmTag.Sha256);
            Assert.Throws<ArgumentException>(() => generator.InitSign(0xFF, PrimaryPrivate()));
        }

        private static byte[] SignedMessage(PgpSignatureGenerator[] generators, byte[] content)
        {
            var bOut = new MemoryStream();

            // one-pass signatures: the first announces the last signature
            for (int i = 0; i < generators.Length; ++i)
            {
                generators[i].GenerateOnePassVersion(isNested: i != generators.Length - 1).Encode(bOut);
            }

            using (Stream literal = new PgpLiteralDataGenerator().Open(bOut, PgpLiteralData.Binary, "", content.Length,
                DateTime.UtcNow))
            {
                literal.Write(content, 0, content.Length);
            }
            foreach (var generator in generators)
            {
                generator.Update(content);
            }

            for (int i = generators.Length - 1; i >= 0; --i)
            {
                generators[i].Generate().Encode(bOut);
            }
            return bOut.ToArray();
        }

        [Test]
        public void OnePassSignedMessage()
        {
            PgpSignatureGenerator generator = InitSign(HashAlgorithmTag.Sha256, PgpSignature.BinaryDocument);
            byte[] message = SignedMessage(new[]{ generator }, Data);

            var factory = new PgpObjectFactory(message);
            var opsList = (PgpOnePassSignatureList)factory.NextPgpObject();
            Assert.That(opsList.Count, Is.EqualTo(1));
            PgpOnePassSignature ops = opsList[0];

            Assert.That(ops.Version, Is.EqualTo(6));
            Assert.That(ops.GetSalt().Length, Is.EqualTo(32 / 2));
            Assert.That(ops.GetFingerprint(), Is.EqualTo(Primary().GetFingerprint()));
            Assert.That(ops.KeyId, Is.EqualTo(Primary().KeyId));

            var literal = (PgpLiteralData)factory.NextPgpObject();
            byte[] content = Streams.ReadAll(literal.GetDataStream());
            Assert.That(content, Is.EqualTo(Data));

            var signatures = (PgpSignatureList)factory.NextPgpObject();
            ops.InitVerify(Primary());
            ops.Update(content);
            Assert.That(ops.Verify(signatures[0]), Is.True);

            // another key or other data do not verify
            var other = new PgpKeyPair(PublicKeyAlgorithmTag.Ed25519,
                PgpEdDsaV4SignatureTest.GenerateKeyPair(PublicKeyAlgorithmTag.Ed25519), DateTime.UtcNow);
            ops.InitVerify(other.PublicKey);
            ops.Update(content);
            Assert.That(ops.Verify(signatures[0]), Is.False);

            ops.InitVerify(Primary());
            ops.Update(Strings.ToUtf8ByteArray("different"));
            Assert.That(ops.Verify(signatures[0]), Is.False);
        }

        [Test]
        public void NestedOnePassSignaturesOfBothVersions()
        {
            var v4Key = new PgpKeyPair(PublicKeyAlgorithmTag.Ed25519,
                PgpEdDsaV4SignatureTest.GenerateKeyPair(PublicKeyAlgorithmTag.Ed25519), DateTime.UtcNow);

            var v4Generator = new PgpSignatureGenerator(PublicKeyAlgorithmTag.Ed25519, HashAlgorithmTag.Sha256);
            v4Generator.InitSign(PgpSignature.BinaryDocument, v4Key.PrivateKey);
            PgpSignatureGenerator v6Generator = InitSign(HashAlgorithmTag.Sha512, PgpSignature.BinaryDocument);

            byte[] message = SignedMessage(new[]{ v4Generator, v6Generator }, Data);

            var factory = new PgpObjectFactory(message);
            var opsList = (PgpOnePassSignatureList)factory.NextPgpObject();
            Assert.That(opsList.Count, Is.EqualTo(2));
            Assert.That(opsList[0].Version, Is.EqualTo(3));
            Assert.That(opsList[1].Version, Is.EqualTo(6));

            var literal = (PgpLiteralData)factory.NextPgpObject();
            byte[] content = Streams.ReadAll(literal.GetDataStream());
            var signatures = (PgpSignatureList)factory.NextPgpObject();
            Assert.That(signatures.Count, Is.EqualTo(2));

            // the last one-pass signature is closed by the first signature
            Assert.That(signatures[0].Version, Is.EqualTo(6));
            Assert.That(signatures[1].Version, Is.EqualTo(4));

            opsList[1].InitVerify(Primary());
            opsList[1].Update(content);
            Assert.That(opsList[1].Verify(signatures[0]), Is.True);

            opsList[0].InitVerify(v4Key.PublicKey);
            opsList[0].Update(content);
            Assert.That(opsList[0].Verify(signatures[1]), Is.True);

            // the pairing of the versions is checked
            opsList[1].InitVerify(Primary());
            opsList[1].Update(content);
            Assert.That(opsList[1].Verify(signatures[1]), Is.False);

            opsList[0].InitVerify(v4Key.PublicKey);
            opsList[0].Update(content);
            Assert.That(opsList[0].Verify(signatures[0]), Is.False);

            // and a one-pass signature only verifies with the key that it names
            opsList[1].InitVerify(v4Key.PublicKey);
            opsList[1].Update(content);
            Assert.That(opsList[1].Verify(signatures[0]), Is.False);
        }

        /// <summary>The salt in a one-pass signature has to match the one of its signature.</summary>
        [Test]
        public void OnePassSignatureSaltMustMatch()
        {
            PgpSignatureGenerator first = InitSign(HashAlgorithmTag.Sha256, PgpSignature.BinaryDocument);
            PgpSignatureGenerator second = InitSign(HashAlgorithmTag.Sha256, PgpSignature.BinaryDocument);

            PgpOnePassSignature ops = first.GenerateOnePassVersion(false);
            first.Update(Data);
            second.Update(Data);
            PgpSignature signature = Reparse(second.Generate());

            // the signature itself is fine, but it belongs to the other one-pass signature
            Assert.That(Verify(signature, Data), Is.True);
            ops = ReparseOps(ops);
            ops.InitVerify(Primary());
            ops.Update(Data);
            Assert.That(ops.Verify(signature), Is.False);
        }

        private static PgpOnePassSignature ReparseOps(PgpOnePassSignature ops) =>
            ((PgpOnePassSignatureList)new PgpObjectFactory(ops.GetEncoded()).NextPgpObject())[0];

        private const string Rfc9580A6Text = "What we need from the grocery store:\r\n\r\n- tofu\r\n- vegetables\r\n"
            + "- noodles\r\n";

        // The inline-signed message of RFC 9580 A.7.
        [Test]
        public void Rfc9580InlineSignedMessage()
        {
            var certificate = new PgpPublicKeyRing(PgpV6TestUtilities.LoadRfc9580("a3-v6-certificate.asc"));
            PgpPublicKey key = certificate.GetPublicKey();

            var factory = new PgpObjectFactory(PgpV6TestUtilities.LoadRfc9580("a7-inline-signed.asc"));
            var opsList = (PgpOnePassSignatureList)factory.NextPgpObject();
            PgpOnePassSignature ops = opsList[0];
            Assert.That(ops.SignatureType, Is.EqualTo(PgpSignature.CanonicalTextDocument));

            var literal = (PgpLiteralData)factory.NextPgpObject();
            byte[] content = Streams.ReadAll(literal.GetDataStream());
            Assert.That(Strings.FromUtf8ByteArray(content).Replace("\r\n", "\n"),
                Is.EqualTo(Rfc9580A6Text.Replace("\r\n", "\n")));

            var signatures = (PgpSignatureList)factory.NextPgpObject();

            ops.InitVerify(key);
            ops.Update(content);
            Assert.That(ops.Verify(signatures[0]), Is.True);

            // the same signature is a regular text signature over the text
            Assert.That(Verify(signatures[0], key, content), Is.True);
        }

        private static bool Verify(PgpSignature signature, PgpPublicKey key, byte[] data)
        {
            signature.InitVerify(key);
            signature.Update(data);
            return signature.Verify();
        }

        // The cleartext message of RFC 9580 A.6, without a Hash header.
        [Test]
        public void Rfc9580CleartextSignedMessage()
        {
            var certificate = new PgpPublicKeyRing(PgpV6TestUtilities.LoadRfc9580("a3-v6-certificate.asc"));
            string armored;
            using (var input = SimpleTestData("a6-cleartext-signed.asc"))
            {
                armored = Strings.FromUtf8ByteArray(Streams.ReadAll(input));
            }
            Assert.That(armored, Does.Not.Contain("Hash:"));

            VerifyCleartext(armored.Replace("\r\n", "\n"), certificate.GetPublicKey(), Rfc9580A6Text);
        }

        private static Stream SimpleTestData(string name) =>
            Org.BouncyCastle.Utilities.Test.SimpleTest.GetTestDataAsStream("openpgp.rfc9580." + name);

        /// <summary>Read a cleartext signed message, and verify its signature over the expected text.</summary>
        private static void VerifyCleartext(string message, PgpPublicKey key, string expectedCanonicalText)
        {
            var aIn = new ArmoredInputStream(new MemoryStream(Strings.ToUtf8ByteArray(message), false));
            string[] headers = aIn.GetArmorHeaders();
            Assert.That(headers == null || headers.Length == 0, Is.True);

            var text = new MemoryStream();
            int ch;
            while ((ch = aIn.ReadByte()) >= 0 && aIn.IsClearText())
            {
                text.WriteByte((byte)ch);
            }

            var signatures = (PgpSignatureList)new PgpObjectFactory(aIn).NextPgpObject();
            PgpSignature signature = signatures[0];
            Assert.That(signature.Version, Is.EqualTo(6));
            Assert.That(signature.SignatureType, Is.EqualTo(PgpSignature.CanonicalTextDocument));

            // the signed text: the lines without trailing white space, separated by CRLF; the stream has already
            // dropped the line ending that precedes the signature header
            string clearText = Strings.FromUtf8ByteArray(text.ToArray()).Replace("\r\n", "\n");
            if (clearText.EndsWith("\n"))
            {
                clearText = clearText.Substring(0, clearText.Length - 1);
            }
            string[] lines = clearText.Split('\n').Select(l => l.TrimEnd(' ', '\t', '\r')).ToArray();
            string canonical = string.Join("\r\n", lines);
            Assert.That(canonical, Is.EqualTo(expectedCanonicalText));

            signature.InitVerify(key);
            signature.Update(Strings.ToUtf8ByteArray(canonical));
            Assert.That(signature.Verify(), Is.True);
        }

        [Test]
        public void CleartextSignatureWithoutHashHeader()
        {
            string[] lines = { "First line", "second line with trailing space  ", "", "- a dashed line", "last line" };

            PgpSignatureGenerator generator = InitSign(HashAlgorithmTag.Sha512, PgpSignature.CanonicalTextDocument);

            var bOut = new MemoryStream();
            var aOut = new ArmoredOutputStream(bOut);
            aOut.BeginClearText();

            for (int i = 0; i < lines.Length; ++i)
            {
                string stripped = lines[i].TrimEnd(' ', '\t');
                if (i > 0)
                {
                    generator.Update((byte)'\r');
                    generator.Update((byte)'\n');
                    aOut.WriteByte((byte)'\n');
                }
                generator.Update(Strings.ToUtf8ByteArray(stripped));
                byte[] line = Strings.ToUtf8ByteArray(lines[i]);
                aOut.Write(line, 0, line.Length);
            }
            // the line ending of the last line, which is not part of the signed text
            aOut.WriteByte((byte)'\n');
            aOut.EndClearText();
            generator.Generate().Encode(new BcpgOutputStream(aOut));
            aOut.Close();

            string armored = Strings.FromUtf8ByteArray(bOut.ToArray());
            Assert.That(armored, Does.Contain("-----BEGIN PGP SIGNATURE-----"));
            Assert.That(armored, Does.StartWith("-----BEGIN PGP SIGNED MESSAGE-----"));
            Assert.That(armored, Does.Not.Contain("Hash:"));
            Assert.That(armored, Does.Contain("- - a dashed line"));

            string canonical = string.Join("\r\n", lines.Select(l => l.TrimEnd(' ', '\t')));
            VerifyCleartext(armored.Replace("\r\n", "\n"), Primary(), canonical);
        }
    }
}
