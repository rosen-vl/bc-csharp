using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;

using NUnit.Framework;

using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Bcpg.OpenPgp.Tests
{
    /// <summary>
    /// Robustness of the parsers and decryptors for version 6 data against corrupt input.
    /// The only acceptable outcomes for a damaged packet are a normal result (identical or "false") or one of the
    /// exceptions that describe invalid data.
    /// </summary>
    [TestFixture]
    public class PgpV6RobustnessTest
    {
        private static readonly SecureRandom Random = new SecureRandom();

        private static readonly byte[] Content = Strings.ToUtf8ByteArray("robustness");

        /// <summary>Run the action; it may return or throw what invalid data causes, and nothing else.</summary>
        private static void Tolerate(Action action, string what)
        {
            try
            {
                action();
            }
            catch (PgpException)
            {
            }
            catch (IOException)
            {
            }
            catch (UnsupportedPacketVersionException)
            {
            }
            catch (Exception e)
            {
                Assert.Fail(what + ": unexpected " + e.GetType().FullName + ": " + e.Message + Environment.NewLine
                    + e.StackTrace);
            }
        }

        /// <summary>Every single-octet mutation of the data, passed to the action.</summary>
        private static void ForEachMutation(byte[] data, Action<byte[]> action, string what, int limit = int.MaxValue)
        {
            for (int i = 0; i < System.Math.Min(data.Length, limit); ++i)
            {
                foreach (byte mask in new byte[]{ 0x01, 0x80, 0xFF })
                {
                    byte[] mutated = Arrays.Clone(data);
                    mutated[i] ^= mask;
                    int position = i;
                    Tolerate(() => action(mutated), what + " octet " + position + " mask " + mask);
                }
            }
        }

        /// <summary>Every truncation of the data, passed to the action.</summary>
        private static void ForEachTruncation(byte[] data, Action<byte[]> action, string what, int step = 1)
        {
            for (int length = 0; length < data.Length; length += step)
            {
                byte[] truncated = Arrays.CopyOf(data, length);
                int position = length;
                Tolerate(() => action(truncated), what + " length " + position);
            }
        }

        private static PgpKeyPair Ed25519Pair(int version)
        {
            var generator = new Ed25519KeyPairGenerator();
            generator.Init(new Ed25519KeyGenerationParameters(Random));
            return new PgpKeyPair(version, PublicKeyAlgorithmTag.Ed25519, generator.GenerateKeyPair(),
                DateTime.UtcNow);
        }

        private static PgpPublicKeyRing A1PublicRing() =>
            new PgpPublicKeyRing(PgpV6TestUtilities.LoadRfc9980("a1-public-key.asc"));

        private static PgpSecretKeyRing A1SecretRing() =>
            new PgpSecretKeyRing(PgpV6TestUtilities.LoadRfc9980("a1-secret-key.asc"));

        private static PgpPrivateKey A1Subkey() => A1SecretRing().GetSecretKeys()
            .First(k => k.PublicKey.Algorithm == PublicKeyAlgorithmTag.MLKem768_X25519).ExtractPrivateKey(new char[0]);

        private static byte[][] Packets(byte[] encoded) => PgpUnsupportedVersionTest.SplitPackets(encoded);

        private static void VerifyBinding(byte[] encoded)
        {
            PgpPublicKeyRing ring = A1PublicRing();
            PgpPublicKey primary = ring.GetPublicKey();
            PgpPublicKey subkey = ring.GetPublicKeys().Last();

            object parsed = new PgpObjectFactory(encoded).NextPgpObject();
            if (parsed is PgpSignatureList list)
            {
                for (int i = 0; i < list.Count; ++i)
                {
                    PgpSignature signature = list[i];
                    signature.InitVerify(primary);
                    signature.VerifyCertification(primary, subkey);
                    signature.GetHashedSubPackets();
                    signature.GetUnhashedSubPackets();
                    signature.GetSalt();
                }
            }
        }

        private static void Decrypt(byte[] message, PgpPrivateKey privateKey)
        {
            object parsed = new PgpObjectFactory(message).NextPgpObject();
            if (!(parsed is PgpEncryptedDataList list))
                return;

            foreach (PgpEncryptedData data in list.GetEncryptedDataObjects())
            {
                if (data is PgpPublicKeyEncryptedData publicData)
                {
                    using (Stream clear = publicData.GetDataStream(privateKey))
                    {
                        Streams.ReadAll(clear);
                    }
                    if (publicData.IsIntegrityProtected())
                    {
                        publicData.Verify();
                    }
                }
            }
        }

        private static void DecryptWithPassPhrase(byte[] message, char[] passPhrase)
        {
            object parsed = new PgpObjectFactory(message).NextPgpObject();
            if (!(parsed is PgpEncryptedDataList list))
                return;

            foreach (PgpEncryptedData data in list.GetEncryptedDataObjects())
            {
                if (data is PgpPbeEncryptedData pbeData)
                {
                    using (Stream clear = pbeData.GetDataStream(passPhrase))
                    {
                        Streams.ReadAll(clear);
                    }
                    if (pbeData.IsIntegrityProtected())
                    {
                        pbeData.Verify();
                    }
                }
            }
        }

        // A version 6 signature (the subkey binding of RFC 9980 A.1).
        [Test]
        public void MutatedSignature()
        {
            byte[] encoded = A1PublicRing().GetPublicKeys().Last().GetSignaturesOfType(PgpSignature.SubkeyBinding)
                .Cast<PgpSignature>().First().GetEncoded();
            Assert.DoesNotThrow(() => VerifyBinding(encoded));

            ForEachMutation(encoded, VerifyBinding, "signature");
        }

        [Test]
        public void MutatedOnePassSignature()
        {
            PgpKeyPair pair = Ed25519Pair(6);
            var generator = new PgpSignatureGenerator(PublicKeyAlgorithmTag.Ed25519, HashAlgorithmTag.Sha256);
            generator.InitSign(PgpSignature.BinaryDocument, pair.PrivateKey);
            var bOut = new MemoryStream();
            generator.GenerateOnePassVersion(false).Encode(bOut);
            byte[] encoded = bOut.ToArray();

            ForEachMutation(encoded, mutated =>
            {
                object parsed = new PgpObjectFactory(mutated).NextPgpObject();
                if (parsed is PgpOnePassSignatureList list)
                {
                    for (int i = 0; i < list.Count; ++i)
                    {
                        PgpOnePassSignature onePass = list[i];
                        onePass.InitVerify(pair.PublicKey);
                        onePass.Update(Content);
                        onePass.GetFingerprint();
                        onePass.GetSalt();
                    }
                }
            }, "one-pass signature");
        }

        // A version 6 PKESK (RFC 9980 A.1.3, ML-KEM-768+X25519).
        [Test]
        public void MutatedPkesk()
        {
            byte[] message = PgpV6TestUtilities.LoadRfc9980("a1-message.asc");
            byte[][] packets = Packets(message);
            PgpPrivateKey privateKey = A1Subkey();

            // the PKESK is more than 1,300 octets long: mutate the header, the key reference and the first fields
            // thoroughly and the rest in steps
            byte[] pkesk = packets[0];
            ForEachMutation(pkesk, mutated => Decrypt(Arrays.Concatenate(mutated, packets[1]), privateKey),
                "PKESK", limit: 120);
            for (int i = 120; i < pkesk.Length; i += 37)
            {
                byte[] mutated = Arrays.Clone(pkesk);
                mutated[i] ^= 0x04;
                int position = i;
                Tolerate(() => Decrypt(Arrays.Concatenate(mutated, packets[1]), privateKey), "PKESK octet " + position);
            }
        }

        [Test]
        public void MutatedSeipdHeader()
        {
            byte[] message = PgpV6TestUtilities.LoadRfc9580("a8-x25519-ocb-message.asc");
            byte[][] packets = Packets(message);
            PgpPrivateKey privateKey = new PgpSecretKeyRing(PgpV6TestUtilities.LoadRfc9580("a4-v6-secret-key.asc"))
                .GetSecretKeys().Last().ExtractPrivateKey(new char[0]);

            // sanity check: the message decrypts
            Assert.DoesNotThrow(() => Decrypt(message, privateKey));

            ForEachMutation(packets[1], mutated => Decrypt(Arrays.Concatenate(packets[0], mutated), privateKey),
                "SEIPD", limit: 80);
            ForEachMutation(packets[0], mutated => Decrypt(Arrays.Concatenate(mutated, packets[1]), privateKey),
                "X25519 PKESK");
        }

        private static byte[] PassPhraseMessage(char[] passPhrase, AeadAlgorithmTag aead, S2k.Argon2Params argon2)
        {
            var generator = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Aes256, aead, 0, Random);
            if (argon2 != null)
            {
                generator.AddMethod(passPhrase, argon2);
            }
            else
            {
                generator.AddMethod(passPhrase, HashAlgorithmTag.Sha256, 0x10);
            }

            var bOut = new MemoryStream();
            using (Stream encrypted = generator.Open(bOut, new byte[1 << 10]))
            using (Stream literal = new PgpLiteralDataGenerator().Open(encrypted, PgpLiteralData.Binary, "",
                DateTime.UtcNow, new byte[1 << 10]))
            {
                literal.Write(Content, 0, Content.Length);
            }
            return bOut.ToArray();
        }

        [Test]
        public void MutatedSkesk()
        {
            char[] passPhrase = "robust".ToCharArray();

            foreach (S2k.Argon2Params argon2 in new S2k.Argon2Params[]{ null, new S2k.Argon2Params(1, 1, 10, Random) })
            {
                byte[] message = PassPhraseMessage(passPhrase, AeadAlgorithmTag.Eax, argon2);
                byte[][] packets = Packets(message);
                Assert.DoesNotThrow(() => DecryptWithPassPhrase(message, passPhrase));

                ForEachMutation(packets[0], mutated =>
                    DecryptWithPassPhrase(Arrays.Concatenate(mutated, packets[1]), passPhrase), "SKESK");
            }
        }

        [Test]
        public void MutatedProtectedSecretKey()
        {
            PgpSecretKeyRing ring = A1SecretRing();
            byte[] passPhrase = Strings.ToUtf8ByteArray("robust");
            PgpSecretKey protectedKey = PgpSecretKey.CopyWithNewProtection(ring.GetSecretKey(), new byte[0],
                PgpSecretKeyProtection.AeadArgon2(SymmetricKeyAlgorithmTag.Aes256, AeadAlgorithmTag.Ocb,
                    new S2k.Argon2Params(1, 1, 10, Random), passPhrase), Random);
            byte[] encoded = protectedKey.GetEncoded();
            Assert.DoesNotThrow(() => new PgpSecretKeyRing(encoded).GetSecretKey().ExtractPrivateKeyRaw(passPhrase));

            ForEachMutation(encoded, mutated =>
                new PgpSecretKeyRing(mutated).GetSecretKey().ExtractPrivateKeyRaw(passPhrase), "secret key");
        }

        [Test]
        public void TruncatedPackets()
        {
            PgpPublicKeyRing publicRing = A1PublicRing();
            byte[] keyRing = publicRing.GetEncoded();
            ForEachTruncation(keyRing, truncated => new PgpPublicKeyRing(truncated), "public key ring", step: 7);

            byte[] secretRing = A1SecretRing().GetEncoded();
            ForEachTruncation(secretRing, truncated => new PgpSecretKeyRing(truncated), "secret key ring", step: 7);

            byte[] message = PgpV6TestUtilities.LoadRfc9580("a8-x25519-ocb-message.asc");
            PgpPrivateKey privateKey = new PgpSecretKeyRing(PgpV6TestUtilities.LoadRfc9580("a4-v6-secret-key.asc"))
                .GetSecretKeys().Last().ExtractPrivateKey(new char[0]);
            ForEachTruncation(message, truncated => Decrypt(truncated, privateKey), "message");

            byte[] signed = PgpV6TestUtilities.LoadRfc9580("a7-inline-signed.asc");
            ForEachTruncation(signed, truncated =>
            {
                var factory = new PgpObjectFactory(truncated);
                PgpObject obj;
                while ((obj = factory.NextPgpObject()) != null)
                {
                    if (obj is PgpLiteralData literal)
                    {
                        Streams.ReadAll(literal.GetInputStream());
                    }
                }
            }, "inline signed message");
        }

        [Test]
        public void RandomCiphertext()
        {
            byte[] message = PgpV6TestUtilities.LoadRfc9580("a8-x25519-ocb-message.asc");
            byte[][] packets = Packets(message);
            PgpPrivateKey privateKey = new PgpSecretKeyRing(PgpV6TestUtilities.LoadRfc9580("a4-v6-secret-key.asc"))
                .GetSecretKeys().Last().ExtractPrivateKey(new char[0]);

            for (int i = 0; i < 100; ++i)
            {
                // keep the header of the SEIPD and make the rest random
                byte[] seipd = Arrays.Clone(packets[1]);
                int start = System.Math.Min(8, seipd.Length);
                byte[] random = SecureRandom.GetNextBytes(Random, seipd.Length - start);
                Array.Copy(random, 0, seipd, start, random.Length);
                Tolerate(() => Decrypt(Arrays.Concatenate(packets[0], seipd), privateKey), "random SEIPD");

                byte[] pkesk = Arrays.Clone(packets[0]);
                int fields = System.Math.Min(40, pkesk.Length);
                random = SecureRandom.GetNextBytes(Random, pkesk.Length - fields);
                Array.Copy(random, 0, pkesk, fields, random.Length);
                Tolerate(() => Decrypt(Arrays.Concatenate(pkesk, packets[1]), privateKey), "random PKESK fields");
            }
        }

        [Test]
        public void PkeskAlgorithmSweep()
        {
            byte[] message = PgpV6TestUtilities.LoadRfc9580("a8-x25519-ocb-message.asc");
            byte[][] packets = Packets(message);
            PgpPrivateKey privateKey = new PgpSecretKeyRing(PgpV6TestUtilities.LoadRfc9580("a4-v6-secret-key.asc"))
                .GetSecretKeys().Last().ExtractPrivateKey(new char[0]);

            // body: version, length of key reference, key version, fingerprint (32), algorithm
            byte[] pkesk = packets[0];
            int algorithmPosition = Array.IndexOf(pkesk, (byte)PublicKeyAlgorithmTag.X25519, 4 + 2);
            Assert.That(algorithmPosition, Is.GreaterThan(0));

            for (int algorithm = 0; algorithm < 256; ++algorithm)
            {
                byte[] modified = Arrays.Clone(pkesk);
                modified[algorithmPosition] = (byte)algorithm;
                int value = algorithm;
                Tolerate(() => Decrypt(Arrays.Concatenate(modified, packets[1]), privateKey), "algorithm " + value);
            }
        }

        [Test]
        public void SignatureAlgorithmSweep()
        {
            PgpPublicKeyRing ring = A1PublicRing();
            byte[] encoded = ring.GetPublicKeys().Last().GetSignaturesOfType(PgpSignature.SubkeyBinding)
                .Cast<PgpSignature>().First().GetEncoded();

            // body: header, version 6, type, public key algorithm, hash algorithm
            int headerLength = encoded[1] < 192 ? 2 : 3;
            Assert.That(encoded[headerLength], Is.EqualTo(6));
            int algorithmPosition = headerLength + 2;

            for (int algorithm = 0; algorithm < 256; ++algorithm)
            {
                byte[] modified = Arrays.Clone(encoded);
                modified[algorithmPosition] = (byte)algorithm;
                int value = algorithm;
                Tolerate(() => VerifyBinding(modified), "signature algorithm " + value);

                modified = Arrays.Clone(encoded);
                modified[algorithmPosition + 1] = (byte)algorithm;
                Tolerate(() => VerifyBinding(modified), "signature hash " + value);
            }
        }

        [Test]
        public void AeadStreamsWithRandomReadSizes()
        {
            for (int i = 0; i < 200; ++i)
            {
                int chunkOctet = Random.Next(0, 5);
                int length = Random.Next(0, 6 * (1 << (chunkOctet + 6)));
                byte[] plaintext = SecureRandom.GetNextBytes(Random, length);
                var aead = new[]{ AeadAlgorithmTag.Eax, AeadAlgorithmTag.Ocb, AeadAlgorithmTag.Gcm }[i % 3];
                char[] passPhrase = "stream".ToCharArray();

                var generator = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Aes128, aead, chunkOctet,
                    Random);
                generator.AddMethod(passPhrase, HashAlgorithmTag.Sha256, 0x01);

                var bOut = new MemoryStream();
                using (Stream encrypted = generator.Open(bOut, new byte[Random.Next(1, 300)]))
                {
                    // write in pieces of random sizes
                    int offset = 0;
                    while (offset < length)
                    {
                        int piece = System.Math.Min(length - offset, Random.Next(1, 200));
                        encrypted.Write(plaintext, offset, piece);
                        offset += piece;
                    }
                }

                var list = (PgpEncryptedDataList)new PgpObjectFactory(bOut.ToArray()).NextPgpObject();
                var data = (PgpPbeEncryptedData)list[0];
                var result = new MemoryStream();
                using (Stream clear = data.GetDataStream(passPhrase))
                {
                    var buffer = new byte[300];
                    int read;
                    while ((read = clear.Read(buffer, 0, Random.Next(1, buffer.Length + 1))) > 0)
                    {
                        result.Write(buffer, 0, read);
                    }
                }
                Assert.That(result.ToArray(), Is.EqualTo(plaintext), "iteration " + i);
                Assert.That(data.Verify(), Is.True, "iteration " + i);
            }
        }

        /// <summary>
        /// A version 2 SEIPD packet that ends early is an error, not the end of the data: the packet reader of the
        /// decrypted stream treats a missing end as a clean end, so the truncation has to be reported by the stream.
        /// </summary>
        [Test]
        public void TruncatedAeadMessageIsAnError()
        {
            PgpPrivateKey privateKey = new PgpSecretKeyRing(PgpV6TestUtilities.LoadRfc9580("a4-v6-secret-key.asc"))
                .GetSecretKeys().Last().ExtractPrivateKey(new char[0]);
            PgpPublicKey publicKey = new PgpPublicKeyRing(PgpV6TestUtilities.LoadRfc9580("a3-v6-certificate.asc"))
                .GetPublicKeys().Last();

            // the SEIPD packet of a message written to a stream has partial lengths, and its last segment ends with
            // the final authentication tag
            byte[] message = PgpV6PkeskTest.EncryptV2(new[]{ publicKey }, Content);

            foreach (int cut in new[]{ 1, 8, 16, 17, 31, 40 })
            {
                byte[] truncated = Arrays.CopyOf(message, message.Length - cut);
                var list = (PgpEncryptedDataList)new PgpObjectFactory(truncated).NextPgpObject();
                var data = (PgpPublicKeyEncryptedData)list[0];
                Stream clear = data.GetDataStream(privateKey);

                Assert.Catch<PgpException>(() =>
                {
                    var factory = new PgpObjectFactory(clear);
                    PgpObject obj;
                    while ((obj = factory.NextPgpObject()) != null)
                    {
                        if (obj is PgpLiteralData literal)
                        {
                            Streams.ReadAll(literal.GetInputStream());
                        }
                    }
                    data.Verify();
                }, "cut " + cut);
            }
        }

        private static void RunConcurrently(int threads, Action<int> work)
        {
            var errors = new List<Exception>();
            var workers = Enumerable.Range(0, threads).Select(index => new Thread(() =>
            {
                try
                {
                    work(index);
                }
                catch (Exception e)
                {
                    lock (errors)
                    {
                        errors.Add(e);
                    }
                }
            })).ToList();

            workers.ForEach(t => t.Start());
            workers.ForEach(t => t.Join());

            Assert.That(errors, Is.Empty, errors.FirstOrDefault()?.ToString());
        }

        [Test]
        public void ConcurrentSigningAndVerification()
        {
            PgpKeyPair pair = Ed25519Pair(6);
            PgpPublicKey shared = pair.PublicKey;

            RunConcurrently(16, index =>
            {
                for (int i = 0; i < 20; ++i)
                {
                    byte[] data = Strings.ToUtf8ByteArray("thread " + index + " round " + i);
                    var generator = new PgpSignatureGenerator(PublicKeyAlgorithmTag.Ed25519, HashAlgorithmTag.Sha512);
                    generator.InitSign(PgpSignature.BinaryDocument, pair.PrivateKey);
                    generator.Update(data);
                    PgpSignature signature = generator.Generate();

                    signature.InitVerify(shared);
                    signature.Update(data);
                    Assert.That(signature.Verify(), Is.True);
                }
            });
        }

        [Test]
        public void ConcurrentDecryption()
        {
            byte[] message = PgpV6TestUtilities.LoadRfc9580("a8-x25519-ocb-message.asc");
            var ring = new PgpSecretKeyRing(PgpV6TestUtilities.LoadRfc9580("a4-v6-secret-key.asc"));
            PgpSecretKey secretKey = ring.GetSecretKeys().Last();

            RunConcurrently(16, index =>
            {
                PgpPrivateKey privateKey = secretKey.ExtractPrivateKey(new char[0]);
                for (int i = 0; i < 10; ++i)
                {
                    var list = (PgpEncryptedDataList)new PgpObjectFactory(message).NextPgpObject();
                    var data = (PgpPublicKeyEncryptedData)list[0];
                    using (Stream clear = data.GetDataStream(privateKey))
                    {
                        Assert.That(Streams.ReadAll(clear).Length, Is.GreaterThan(0));
                    }
                    Assert.That(data.Verify(), Is.True);
                }
            });
        }
    }
}
