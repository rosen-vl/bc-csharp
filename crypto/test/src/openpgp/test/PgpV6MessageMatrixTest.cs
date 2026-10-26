using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

using NUnit.Framework;

using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Bcpg.OpenPgp.Tests
{
    /// <summary>
    /// End-to-end composition matrix through the public API: every encryption format, compression algorithm, signer
    /// combination (none, v4, v6, post-quantum v6, and v4 and v6 nested), literal data format and armouring, with
    /// recipients of every encryption algorithm and payload sizes around the chunk and partial-length boundaries.
    /// Each message is produced the way an application would and read back the way an application would.
    /// </summary>
    [TestFixture]
    public class PgpV6MessageMatrixTest
    {
        private static readonly SecureRandom Random = new SecureRandom();

        public enum Format { SeipdV1, SeipdV2Ocb, SeipdV2Gcm, SeipdV2Eax }

        public enum Signers { None, V4EdDsaLegacy, V6Ed25519, V6MLDsa65, V4AndV6Nested }

        private sealed class Recipient
        {
            internal string Name;
            internal PgpPublicKey PublicKey;
            internal PgpPrivateKey PrivateKey;
        }

        private sealed class Signer
        {
            internal PgpKeyPair Pair;
            internal HashAlgorithmTag Hash;
        }

        private static readonly Lazy<Recipient[]> Recipients = new Lazy<Recipient[]>(CreateRecipients);
        private static readonly Lazy<Signer> V4Signer = new Lazy<Signer>(() => new Signer
        {
            Pair = new PgpKeyPair(PublicKeyAlgorithmTag.EdDsa_Legacy, NewEd25519(), DateTime.UtcNow),
            Hash = HashAlgorithmTag.Sha256,
        });
        private static readonly Lazy<Signer> V6Signer = new Lazy<Signer>(() => new Signer
        {
            Pair = new PgpKeyPair(6, PublicKeyAlgorithmTag.Ed25519, NewEd25519(), DateTime.UtcNow),
            Hash = HashAlgorithmTag.Sha512,
        });
        private static readonly Lazy<Signer> PqSigner = new Lazy<Signer>(() => new Signer
        {
            Pair = PgpMLDsaEdDsaTest.NewKeyPair(PublicKeyAlgorithmTag.MLDsa65_Ed25519),
            Hash = HashAlgorithmTag.Sha3_256,
        });

        private static Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair NewEd25519()
        {
            var generator = new Ed25519KeyPairGenerator();
            generator.Init(new Ed25519KeyGenerationParameters(Random));
            return generator.GenerateKeyPair();
        }

        private static Recipient[] CreateRecipients()
        {
            var recipients = new List<Recipient>();

            var mlKem768 = new MLKem768X25519PrivateKeyParameters(Random);
            var pair768 = new PgpKeyPair(6, PublicKeyAlgorithmTag.MLKem768_X25519, mlKem768.GeneratePublicKey(),
                mlKem768, DateTime.UtcNow);
            recipients.Add(new Recipient{ Name = "ML-KEM-768+X25519 v6", PublicKey = pair768.PublicKey,
                PrivateKey = pair768.PrivateKey });

            var mlKem1024 = new MLKem1024X448PrivateKeyParameters(Random);
            var pair1024 = new PgpKeyPair(6, PublicKeyAlgorithmTag.MLKem1024_X448, mlKem1024.GeneratePublicKey(),
                mlKem1024, DateTime.UtcNow);
            recipients.Add(new Recipient{ Name = "ML-KEM-1024+X448 v6", PublicKey = pair1024.PublicKey,
                PrivateKey = pair1024.PrivateKey });

            var v4Kem = new MLKem768X25519PrivateKeyParameters(Random);
            var pairV4 = new PgpKeyPair(4, PublicKeyAlgorithmTag.MLKem768_X25519, v4Kem.GeneratePublicKey(), v4Kem,
                DateTime.UtcNow);
            recipients.Add(new Recipient{ Name = "ML-KEM-768+X25519 v4", PublicKey = pairV4.PublicKey,
                PrivateKey = pairV4.PrivateKey });

            foreach (var algorithm in new[]{ PublicKeyAlgorithmTag.X25519, PublicKeyAlgorithmTag.X448 })
            {
                var pair = new PgpKeyPair(6, algorithm, PgpV6KeyGenerationTest.GenerateX(algorithm), DateTime.UtcNow);
                recipients.Add(new Recipient{ Name = algorithm + " v6", PublicKey = pair.PublicKey,
                    PrivateKey = pair.PrivateKey });
            }

            var x25519Gen = new X25519KeyPairGenerator();
            x25519Gen.Init(new X25519KeyGenerationParameters(Random));
            var legacy = new PgpKeyPair(PublicKeyAlgorithmTag.ECDH, x25519Gen.GenerateKeyPair(), DateTime.UtcNow);
            recipients.Add(new Recipient{ Name = "ECDH Curve25519Legacy v4", PublicKey = legacy.PublicKey,
                PrivateKey = legacy.PrivateKey });

            var rsa = new PgpKeyPair(6, PublicKeyAlgorithmTag.RsaGeneral, PgpV6KeyGenerationTest.GenerateRsa(),
                DateTime.UtcNow);
            recipients.Add(new Recipient{ Name = "RSA v6", PublicKey = rsa.PublicKey, PrivateKey = rsa.PrivateKey });

            return recipients.ToArray();
        }

        private static readonly int[] PayloadSizes = { 0, 1, 255, 256, 257, 4096, 70000 };

        private static IEnumerable<TestCaseData> Cases()
        {
            int index = 0;
            foreach (Format format in Enum.GetValues(typeof(Format)))
            {
                foreach (CompressionAlgorithmTag compression in new[]{ CompressionAlgorithmTag.Uncompressed,
                    CompressionAlgorithmTag.Zip, CompressionAlgorithmTag.ZLib, CompressionAlgorithmTag.BZip2 })
                {
                    foreach (Signers signers in Enum.GetValues(typeof(Signers)))
                    {
                        foreach (char literal in new[]{ PgpLiteralData.Binary, PgpLiteralData.Text,
                            PgpLiteralData.Utf8 })
                        {
                            foreach (bool armor in new[]{ false, true })
                            {
                                int size = PayloadSizes[index % PayloadSizes.Length];
                                int recipient = index % 7;
                                yield return new TestCaseData(format, compression, signers, literal, armor, size,
                                    recipient).SetName(
                                    $"{{m}}({format},{compression},{signers},{literal},armor={armor}," +
                                    $"{size},r{recipient})");
                                ++index;
                            }
                        }
                    }
                }
            }
        }

        private static byte[] Payload(int size, char literal)
        {
            if (literal == PgpLiteralData.Binary)
                return SecureRandom.GetNextBytes(Random, size);

            // text with every kind of line ending and some non-ASCII UTF-8, cut to the size
            string line = "line é中\U0001F600 end\r\nnext\nbare cr\rtrailing  \r\n";
            var text = new System.Text.StringBuilder();
            while (text.Length < size)
            {
                text.Append(line);
            }
            return Arrays.CopyOfRange(Strings.ToUtf8ByteArray(text.ToString()), 0, size);
        }

        private static List<Signer> SignersFor(Signers signers)
        {
            switch (signers)
            {
            case Signers.V4EdDsaLegacy: return new List<Signer>{ V4Signer.Value };
            case Signers.V6Ed25519: return new List<Signer>{ V6Signer.Value };
            case Signers.V6MLDsa65: return new List<Signer>{ PqSigner.Value };
            case Signers.V4AndV6Nested: return new List<Signer>{ V4Signer.Value, V6Signer.Value, PqSigner.Value };
            default: return new List<Signer>();
            }
        }

        private static PgpEncryptedDataGenerator NewGenerator(Format format)
        {
            switch (format)
            {
            case Format.SeipdV1:
                return new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Aes256, true, Random);
            case Format.SeipdV2Ocb:
                return new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Aes256, AeadAlgorithmTag.Ocb, 2, Random);
            case Format.SeipdV2Gcm:
                return new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Aes128, AeadAlgorithmTag.Gcm, 0, Random);
            default:
                return new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Camellia256, AeadAlgorithmTag.Eax, 1,
                    Random);
            }
        }

        [TestCaseSource(nameof(Cases))]
        public void ComposeAndRead(Format format, CompressionAlgorithmTag compression, Signers signers, char literal,
            bool armor, int size, int recipientIndex)
        {
            Recipient recipient = Recipients.Value[recipientIndex];
            byte[] content = Payload(size, literal);
            List<Signer> signerList = SignersFor(signers);
            bool padded = format != Format.SeipdV1 && size % 2 == 0;
            // a definite-length outer packet is only possible without compression (the compressed size is unknown)
            bool definite = compression == CompressionAlgorithmTag.Uncompressed && signerList.Count == 0 && !padded;

            byte[] message = Compose(format, compression, signerList, literal, armor, content, recipient, padded,
                definite);
            Read(message, armor, format, recipient, signerList, literal, content, padded);
        }

        private static byte[] Compose(Format format, CompressionAlgorithmTag compression, List<Signer> signerList,
            char literal, bool armor, byte[] content, Recipient recipient, bool padded, bool definite)
        {
            var output = new MemoryStream();
            Stream outer = armor ? (Stream)new ArmoredOutputStream(output) : output;

            PgpEncryptedDataGenerator encGen = NewGenerator(format);
            encGen.AddMethod(recipient.PublicKey);

            int signatureType = literal == PgpLiteralData.Binary
                ? PgpSignature.BinaryDocument : PgpSignature.CanonicalTextDocument;

            var generators = new List<PgpSignatureGenerator>();
            foreach (Signer signer in signerList)
            {
                var sGen = new PgpSignatureGenerator(signer.Pair.PublicKey.Algorithm, signer.Hash);
                sGen.InitSign(signatureType, signer.Pair.PrivateKey, Random);
                generators.Add(sGen);
            }

            if (definite)
            {
                // literal header: format, name length, name, date; the literal packet header itself
                var literalPacket = new MemoryStream();
                using (Stream litOut = new PgpLiteralDataGenerator().Open(literalPacket, literal, "name.txt",
                    content.Length, new DateTime(2026, 10, 4, 0, 0, 0, DateTimeKind.Utc)))
                {
                    litOut.Write(content, 0, content.Length);
                }
                byte[] inner = literalPacket.ToArray();
                using (Stream encOut = encGen.Open(outer, inner.Length))
                {
                    encOut.Write(inner, 0, inner.Length);
                }
            }
            else
            {
                using (Stream encOut = encGen.Open(outer, new byte[1 << 8]))
                {
                    var compGen = compression == CompressionAlgorithmTag.Uncompressed
                        ? null : new PgpCompressedDataGenerator(compression);
                    Stream compOut = compGen == null ? encOut : compGen.Open(encOut, new byte[1 << 9]);

                    for (int i = 0; i < generators.Count; ++i)
                    {
                        generators[i].GenerateOnePassVersion(i < generators.Count - 1).Encode(compOut);
                    }

                    using (Stream litOut = new PgpLiteralDataGenerator().Open(compOut, literal, "name.txt",
                        new DateTime(2026, 10, 4, 0, 0, 0, DateTimeKind.Utc), new byte[1 << 6]))
                    {
                        // odd write sizes, so that partial lengths and chunk boundaries fall inside writes
                        for (int pos = 0; pos < content.Length; pos += 37)
                        {
                            int n = System.Math.Min(37, content.Length - pos);
                            litOut.Write(content, pos, n);
                            foreach (var sGen in generators)
                            {
                                sGen.Update(content, pos, n);
                            }
                        }
                    }

                    for (int i = generators.Count - 1; i >= 0; --i)
                    {
                        generators[i].Generate().Encode(compOut);
                    }

                    if (compGen != null)
                    {
                        compGen.Close();
                    }

                    if (padded)
                    {
                        new PaddingPacket(33, Random).Encode(new BcpgOutputStream(encOut));
                    }
                }
            }

            if (armor)
            {
                outer.Dispose();
            }
            return output.ToArray();
        }

        private static void Read(byte[] message, bool armor, Format format, Recipient recipient,
            List<Signer> signerList, char literal, byte[] content, bool padded)
        {
            Stream input = new MemoryStream(message, false);
            if (armor)
            {
                input = new ArmoredInputStream(input);
            }

            var list = (PgpEncryptedDataList)new PgpObjectFactory(input).NextPgpObject();
            Assert.That(list.Count, Is.EqualTo(1));
            var encData = (PgpPublicKeyEncryptedData)list[0];
            Assert.That(encData.Version, Is.EqualTo(format == Format.SeipdV1 ? 3 : 6));
            Assert.That(encData.IsAead, Is.EqualTo(format != Format.SeipdV1));
            Assert.That(encData.KeyId, Is.EqualTo(recipient.PublicKey.KeyId));

            var factory = new PgpObjectFactory(encData.GetDataStream(recipient.PrivateKey));
            PgpObject obj = factory.NextPgpObject();
            if (obj is PgpCompressedData compressed)
            {
                factory = new PgpObjectFactory(compressed.GetDataStream());
                obj = factory.NextPgpObject();
            }

            PgpOnePassSignatureList opsList = null;
            if (obj is PgpOnePassSignatureList)
            {
                opsList = (PgpOnePassSignatureList)obj;
                Assert.That(opsList.Count, Is.EqualTo(signerList.Count));
                for (int i = 0; i < opsList.Count; ++i)
                {
                    opsList[i].InitVerify(signerList[i].Pair.PublicKey);
                }
                obj = factory.NextPgpObject();
            }
            else
            {
                Assert.That(signerList.Count, Is.EqualTo(0));
            }

            var literalData = (PgpLiteralData)obj;
            Assert.That(literalData.Format, Is.EqualTo((int)literal));
            Assert.That(literalData.FileName, Is.EqualTo("name.txt"));

            var received = new MemoryStream();
            using (Stream data = literalData.GetDataStream())
            {
                byte[] buffer = new byte[61];
                int n;
                while ((n = data.Read(buffer, 0, buffer.Length)) > 0)
                {
                    received.Write(buffer, 0, n);
                    if (opsList != null)
                    {
                        for (int i = 0; i < opsList.Count; ++i)
                        {
                            opsList[i].Update(buffer, 0, n);
                        }
                    }
                }
            }
            Assert.That(received.ToArray(), Is.EqualTo(content));

            if (opsList != null)
            {
                var signatures = (PgpSignatureList)factory.NextPgpObject();
                Assert.That(signatures.Count, Is.EqualTo(opsList.Count));
                for (int i = 0; i < opsList.Count; ++i)
                {
                    PgpSignature signature = signatures[opsList.Count - 1 - i];
                    Assert.That(signature.Version, Is.EqualTo(signerList[i].Pair.PublicKey.Version == 6 ? 6 : 4));
                    Assert.That(opsList[i].Verify(signature), Is.True, "signature " + i);
                }
            }

            PgpObject trailing = factory.NextPgpObject();
            if (padded && trailing is PgpPadding)
            {
                trailing = factory.NextPgpObject();
            }
            Assert.That(trailing, Is.Null);
            Assert.That(encData.Verify(), Is.True);
        }

        /// <summary>
        /// Every recipient algorithm in one message, in both formats, and each recipient decrypts it: the session key
        /// encodings of all algorithms side by side (v3 and v6 PKESK).
        /// </summary>
        [Test]
        public void AllRecipientsInOneMessage([Values(Format.SeipdV1, Format.SeipdV2Ocb)] Format format)
        {
            byte[] content = SecureRandom.GetNextBytes(Random, 5000);
            PgpEncryptedDataGenerator encGen = NewGenerator(format);
            foreach (Recipient recipient in Recipients.Value)
            {
                encGen.AddMethod(recipient.PublicKey);
            }
            encGen.AddMethodRaw(Strings.ToUtf8ByteArray("and a pass phrase"), HashAlgorithmTag.Sha256);

            var output = new MemoryStream();
            using (Stream encOut = encGen.Open(output, new byte[1 << 10]))
            using (Stream litOut = new PgpLiteralDataGenerator().Open(encOut, PgpLiteralData.Binary, "", content.Length,
                DateTime.UtcNow))
            {
                litOut.Write(content, 0, content.Length);
            }

            foreach (Recipient recipient in Recipients.Value)
            {
                var list = (PgpEncryptedDataList)new PgpObjectFactory(output.ToArray()).NextPgpObject();
                Assert.That(list.Count, Is.EqualTo(Recipients.Value.Length + 1));
                var encData = list.GetEncryptedDataObjects().OfType<PgpPublicKeyEncryptedData>()
                    .Single(d => d.KeyId == recipient.PublicKey.KeyId);
                var literal = (PgpLiteralData)new PgpObjectFactory(encData.GetDataStream(recipient.PrivateKey))
                    .NextPgpObject();
                Assert.That(Streams.ReadAll(literal.GetDataStream()), Is.EqualTo(content), recipient.Name);
                Assert.That(encData.Verify(), Is.True, recipient.Name);
            }

            var pbeList = (PgpEncryptedDataList)new PgpObjectFactory(output.ToArray()).NextPgpObject();
            var pbe = pbeList.GetEncryptedDataObjects().OfType<PgpPbeEncryptedData>().Single();
            var pbeLiteral = (PgpLiteralData)new PgpObjectFactory(
                pbe.GetDataStreamRaw(Strings.ToUtf8ByteArray("and a pass phrase"))).NextPgpObject();
            Assert.That(Streams.ReadAll(pbeLiteral.GetDataStream()), Is.EqualTo(content));
        }

        /// <summary>
        /// A recipient's private key from a different key never yields plaintext, whatever the format: the uniform
        /// error for every wrong key of every algorithm.
        /// </summary>
        [Test]
        public void WrongPrivateKeysAreRejectedUniformly([Values(Format.SeipdV1, Format.SeipdV2Gcm)] Format format)
        {
            byte[] content = Strings.ToUtf8ByteArray("for one recipient only");
            Recipient[] recipients = Recipients.Value;
            for (int i = 0; i < recipients.Length; ++i)
            {
                PgpEncryptedDataGenerator encGen = NewGenerator(format);
                encGen.AddMethod(recipients[i].PublicKey);
                var output = new MemoryStream();
                using (Stream encOut = encGen.Open(output, new byte[1 << 8]))
                using (Stream litOut = new PgpLiteralDataGenerator().Open(encOut, PgpLiteralData.Binary, "",
                    content.Length, DateTime.UtcNow))
                {
                    litOut.Write(content, 0, content.Length);
                }

                for (int j = 0; j < recipients.Length; ++j)
                {
                    if (i == j)
                        continue;

                    var list = (PgpEncryptedDataList)new PgpObjectFactory(output.ToArray()).NextPgpObject();
                    var encData = (PgpPublicKeyEncryptedData)list[0];
                    var e = Assert.Catch<PgpException>(() => encData.GetDataStream(recipients[j].PrivateKey),
                        recipients[i].Name + " decrypted with " + recipients[j].Name);
                    if (format != Format.SeipdV1)
                    {
                        // version 6 PKESKs: one message for every failure (RFC 9580 13.5)
                        Assert.That(e.Message, Is.EqualTo("exception decrypting session key"),
                            recipients[i].Name + " with " + recipients[j].Name);
                    }
                }
            }
        }
    }
}
