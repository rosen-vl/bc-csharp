using System;
using System.Diagnostics;
using System.IO;

using NUnit.Framework;

using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Bcpg.OpenPgp.Tests
{
    /// <summary>
    /// Performance measurements for version 6 OpenPGP and the algorithms of RFC 9980.
    /// Explicit: run on demand. The thresholds are deliberately generous and only catch pathological regressions.
    /// </summary>
    [TestFixture, Explicit, Category("Performance")]
    public class PgpV6PerformanceTest
    {
        private static readonly SecureRandom Random = new SecureRandom();

        private static double MillisecondsPerOperation(int iterations, Action operation)
        {
            operation(); // warm up
            var stopwatch = Stopwatch.StartNew();
            for (int i = 0; i < iterations; ++i)
            {
                operation();
            }
            return stopwatch.Elapsed.TotalMilliseconds / iterations;
        }

        private static readonly PublicKeyAlgorithmTag[] SignatureAlgorithms =
        {
            PublicKeyAlgorithmTag.Ed25519, PublicKeyAlgorithmTag.MLDsa65_Ed25519, PublicKeyAlgorithmTag.MLDsa87_Ed448,
            PublicKeyAlgorithmTag.SlhDsa_Shake128s, PublicKeyAlgorithmTag.SlhDsa_Shake128f,
            PublicKeyAlgorithmTag.SlhDsa_Shake256s,
        };

        private static PgpKeyPair NewSigningPair(PublicKeyAlgorithmTag algorithm)
        {
            switch (algorithm)
            {
            case PublicKeyAlgorithmTag.Ed25519:
            {
                var generator = new Ed25519KeyPairGenerator();
                generator.Init(new Ed25519KeyGenerationParameters(Random));
                return new PgpKeyPair(6, algorithm, generator.GenerateKeyPair(), DateTime.UtcNow);
            }
            case PublicKeyAlgorithmTag.MLDsa65_Ed25519:
            case PublicKeyAlgorithmTag.MLDsa87_Ed448:
                return PgpMLDsaEdDsaTest.NewKeyPair(algorithm);
            default:
                return PgpSlhDsaTest.NewKeyPair(algorithm);
            }
        }

        [Test]
        public void SignatureAlgorithmCosts()
        {
            byte[] data = new byte[1024];

            foreach (var algorithm in SignatureAlgorithms)
            {
                // the slow SLH-DSA parameter sets are measured over fewer iterations
                int iterations = algorithm == PublicKeyAlgorithmTag.SlhDsa_Shake128s ||
                    algorithm == PublicKeyAlgorithmTag.SlhDsa_Shake256s ? 2 : 10;

                double keyGeneration = MillisecondsPerOperation(iterations, () => NewSigningPair(algorithm));
                PgpKeyPair pair = NewSigningPair(algorithm);

                PgpSignature signature = null;
                double sign = MillisecondsPerOperation(iterations, () =>
                {
                    var generator = new PgpSignatureGenerator(algorithm, HashAlgorithmTag.Sha512);
                    generator.InitSign(PgpSignature.BinaryDocument, pair.PrivateKey);
                    generator.Update(data);
                    signature = generator.Generate();
                });

                byte[] encoded = signature.GetEncoded();
                double verify = MillisecondsPerOperation(iterations, () =>
                {
                    var parsed = ((PgpSignatureList)new PgpObjectFactory(encoded).NextPgpObject())[0];
                    parsed.InitVerify(pair.PublicKey);
                    parsed.Update(data);
                    Assert.That(parsed.Verify(), Is.True);
                });

                TestContext.WriteLine($"{algorithm,-22} key generation {keyGeneration,9:F2} ms  sign {sign,9:F2} ms  " +
                    $"verify {verify,8:F2} ms  public key {pair.PublicKey.PublicKeyPacket.GetEncoded().Length,5} B  " +
                    $"signature {encoded.Length,6} B");

                Assert.That(sign, Is.LessThan(60000));
                Assert.That(verify, Is.LessThan(10000));
            }
        }

        private static PgpKeyPair NewKemPair(PublicKeyAlgorithmTag algorithm, int version)
        {
            switch (algorithm)
            {
            case PublicKeyAlgorithmTag.X25519:
            {
                var generator = new X25519KeyPairGenerator();
                generator.Init(new X25519KeyGenerationParameters(Random));
                return new PgpKeyPair(version, algorithm, generator.GenerateKeyPair(), DateTime.UtcNow);
            }
            case PublicKeyAlgorithmTag.MLKem768_X25519:
            {
                var key = new MLKem768X25519PrivateKeyParameters(Random);
                return new PgpKeyPair(version, algorithm, key.GeneratePublicKey(), key, DateTime.UtcNow);
            }
            default:
            {
                var key = new MLKem1024X448PrivateKeyParameters(Random);
                return new PgpKeyPair(version, algorithm, key.GeneratePublicKey(), key, DateTime.UtcNow);
            }
            }
        }

        [Test]
        public void KemCosts()
        {
            byte[] content = new byte[64];

            foreach (var algorithm in new[]
            {
                PublicKeyAlgorithmTag.X25519, PublicKeyAlgorithmTag.MLKem768_X25519,
                PublicKeyAlgorithmTag.MLKem1024_X448,
            })
            {
                double keyGeneration = MillisecondsPerOperation(20, () => NewKemPair(algorithm, 6));
                PgpKeyPair pair = NewKemPair(algorithm, 6);

                double encrypt1 = MillisecondsPerOperation(100,
                    () => PgpMLKemX25519Test.Encrypt(new[]{ pair.PublicKey }, content));
                double encrypt2 = MillisecondsPerOperation(100,
                    () => PgpV6PkeskTest.EncryptV2(new[]{ pair.PublicKey }, content));

                byte[] message1 = PgpMLKemX25519Test.Encrypt(new[]{ pair.PublicKey }, content);
                byte[] message2 = PgpV6PkeskTest.EncryptV2(new[]{ pair.PublicKey }, content);
                double decrypt1 = MillisecondsPerOperation(100,
                    () => PgpMLKemX25519Test.Decrypt(message1, pair.PrivateKey));
                double decrypt2 = MillisecondsPerOperation(100,
                    () => PgpMLKemX25519Test.Decrypt(message2, pair.PrivateKey));

                TestContext.WriteLine($"{algorithm,-18} key generation {keyGeneration,7:F3} ms  " +
                    $"encrypt v3/v1 {encrypt1,7:F3} ms  v6/v2 {encrypt2,7:F3} ms  " +
                    $"decrypt v3/v1 {decrypt1,7:F3} ms  v6/v2 {decrypt2,7:F3} ms  " +
                    $"message {message1.Length} B / {message2.Length} B");

                Assert.That(encrypt2, Is.LessThan(1000));
                Assert.That(decrypt2, Is.LessThan(1000));
            }
        }

        [Test]
        public void SeipdThroughput()
        {
            const int megabytes = 16;
            byte[] data = new byte[megabytes << 20];
            Random.NextBytes(data);
            char[] passPhrase = "throughput".ToCharArray();

            double Throughput(Func<PgpEncryptedDataGenerator> newGenerator)
            {
                var stopwatch = Stopwatch.StartNew();
                var bOut = new MemoryStream();
                PgpEncryptedDataGenerator generator = newGenerator();
                generator.AddMethod(passPhrase, HashAlgorithmTag.Sha256, 0x01);
                using (Stream encrypted = generator.Open(bOut, new byte[1 << 16]))
                {
                    encrypted.Write(data, 0, data.Length);
                }

                var list = (PgpEncryptedDataList)new PgpObjectFactory(bOut.ToArray()).NextPgpObject();
                using (Stream clear = ((PgpPbeEncryptedData)list[0]).GetDataStream(passPhrase))
                {
                    Streams.ReadAll(clear);
                }
                return 2.0 * megabytes / stopwatch.Elapsed.TotalSeconds;
            }

            double v1 = Throughput(() => new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Aes256, true, Random));
            TestContext.WriteLine($"SEIPD v1 (CFB + SHA-1)  {v1,8:F1} MiB/s (encrypt + decrypt)");

            foreach (var aead in new[]{ AeadAlgorithmTag.Eax, AeadAlgorithmTag.Ocb, AeadAlgorithmTag.Gcm })
            {
                double v2 = Throughput(() => new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Aes256, aead, 6,
                    Random));
                TestContext.WriteLine($"SEIPD v2 AES-256/{aead,-4}   {v2,8:F1} MiB/s (encrypt + decrypt)");
                Assert.That(v2, Is.GreaterThan(0.5));
            }
        }

        [Test]
        public void Argon2Cost()
        {
            PgpKeyPair pair = NewSigningPair(PublicKeyAlgorithmTag.Ed25519);
            byte[] passPhrase = Strings.ToUtf8ByteArray("argon2");
            var generator = new PgpKeyRingGenerator(pair, HashAlgorithmTag.Sha256, null, null,
                PgpSecretKeyProtection.AeadArgon2(SymmetricKeyAlgorithmTag.Aes256, AeadAlgorithmTag.Ocb,
                    S2k.Argon2Params.MemoryConstrainedParameters(Random), passPhrase), Random);

            PgpSecretKey key = generator.GenerateSecretKeyRing().GetSecretKey();
            double unlock = MillisecondsPerOperation(3, () => key.ExtractPrivateKeyRaw(passPhrase));

            TestContext.WriteLine($"unlock with Argon2id (t=3, p=4, 64 MiB): {unlock:F1} ms");
            Assert.That(unlock, Is.LessThan(30000));
        }

        [Test]
        public void Sizes()
        {
            foreach (var algorithm in SignatureAlgorithms)
            {
                PgpKeyPair pair = NewSigningPair(algorithm);
                int length = pair.PublicKey.PublicKeyPacket.GetEncoded().Length;
                TestContext.WriteLine($"{algorithm,-22} public key packet {length,5} B");
            }

            foreach (var algorithm in new[]
            {
                PublicKeyAlgorithmTag.MLKem768_X25519, PublicKeyAlgorithmTag.MLKem1024_X448,
            })
            {
                PgpKeyPair pair = NewKemPair(algorithm, 6);
                byte[] message = PgpV6PkeskTest.EncryptV2(new[]{ pair.PublicKey }, new byte[0]);
                int length = pair.PublicKey.PublicKeyPacket.GetEncoded().Length;
                TestContext.WriteLine($"{algorithm,-22} public key packet {length,5} B  message {message.Length} B");
                Assert.That(message.Length, Is.GreaterThan(1000));
            }
        }
    }
}
