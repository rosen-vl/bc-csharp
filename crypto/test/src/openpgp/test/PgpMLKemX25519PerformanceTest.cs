using System;
using System.Diagnostics;
using System.IO;

using NUnit.Framework;

using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Bcpg.OpenPgp.Tests
{
    /// <summary>
    /// Performance measurements for ML-KEM-768+X25519 in OpenPGP, compared with legacy ECDH (Curve25519). Explicit:
    /// run on demand. The thresholds are deliberately generous and only catch pathological regressions.
    /// </summary>
    [TestFixture, Explicit, Category("Performance")]
    public class PgpMLKemX25519PerformanceTest
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

        private static (PgpPublicKey, PgpPrivateKey) EcdhKey()
        {
            var xGen = new X25519KeyPairGenerator();
            xGen.Init(new X25519KeyGenerationParameters(Random));
            var keyPair = new PgpKeyPair(PublicKeyAlgorithmTag.ECDH, xGen.GenerateKeyPair(), DateTime.UtcNow);
            var krg = new PgpKeyRingGenerator(PgpSignature.PositiveCertification,
                PgpMLKemX25519Test.NewEdDsaKeyPair(), "ecdh", SymmetricKeyAlgorithmTag.Null, HashAlgorithmTag.Sha256,
                new char[0], false, null, null, Random);
            krg.AddSubKey(keyPair, HashAlgorithmTag.Sha256);
            PgpSecretKey subkey = null;
            foreach (PgpSecretKey key in krg.GenerateSecretKeyRing().GetSecretKeys())
            {
                subkey = key;
            }
            return (subkey.PublicKey, subkey.ExtractPrivateKey(new char[0]));
        }

        [Test]
        public void KeyEncapsulationCost()
        {
            const int iterations = 200;
            byte[] content = new byte[64];

            double keyGen = MillisecondsPerOperation(50, () => new MLKem768X25519PrivateKeyParameters(Random));

            PgpSecretKeyRing secretRing = PgpMLKemX25519Test.GenerateRing("perf", null,
                out PgpPublicKeyRing publicRing);
            PgpPublicKey pqPublic = PgpMLKemX25519Test.MLKemSubkey(publicRing);
            PgpPrivateKey pqPrivate = PgpMLKemX25519Test.MLKemSubkey(secretRing).ExtractPrivateKey(new char[0]);
            (PgpPublicKey ecdhPublic, PgpPrivateKey ecdhPrivate) = EcdhKey();

            byte[] pqMessage = PgpMLKemX25519Test.Encrypt(new[]{ pqPublic }, content);
            byte[] ecdhMessage = PgpMLKemX25519Test.Encrypt(new[]{ ecdhPublic }, content);

            double pqEncrypt = MillisecondsPerOperation(iterations,
                () => PgpMLKemX25519Test.Encrypt(new[]{ pqPublic }, content));
            double ecdhEncrypt = MillisecondsPerOperation(iterations,
                () => PgpMLKemX25519Test.Encrypt(new[]{ ecdhPublic }, content));
            double pqDecrypt = MillisecondsPerOperation(iterations,
                () => PgpMLKemX25519Test.Decrypt(pqMessage, pqPrivate));
            double ecdhDecrypt = MillisecondsPerOperation(iterations,
                () => PgpMLKemX25519Test.Decrypt(ecdhMessage, ecdhPrivate));
            double extract = MillisecondsPerOperation(50,
                () => PgpMLKemX25519Test.MLKemSubkey(secretRing).ExtractPrivateKey(new char[0]));

            TestContext.WriteLine($"composite key generation:        {keyGen:F3} ms");
            TestContext.WriteLine($"secret key extraction (expand):  {extract:F3} ms");
            TestContext.WriteLine($"encrypt 64 B, ML-KEM-768+X25519: {pqEncrypt:F3} ms  (ECDH: {ecdhEncrypt:F3} ms)");
            TestContext.WriteLine($"decrypt 64 B, ML-KEM-768+X25519: {pqDecrypt:F3} ms  (ECDH: {ecdhDecrypt:F3} ms)");
            TestContext.WriteLine($"message size: {pqMessage.Length} B  (ECDH: {ecdhMessage.Length} B)");

            Assert.That(pqEncrypt, Is.LessThan(25.0));
            Assert.That(pqDecrypt, Is.LessThan(25.0));
            Assert.That(keyGen, Is.LessThan(25.0));
        }

        [Test]
        public void LargePayloadStreaming()
        {
            const int length = 64 * 1024 * 1024;
            PgpSecretKeyRing secretRing = PgpMLKemX25519Test.GenerateRing("perf", null,
                out PgpPublicKeyRing publicRing);
            PgpPrivateKey privateKey = PgpMLKemX25519Test.MLKemSubkey(secretRing).ExtractPrivateKey(new char[0]);

            byte[] chunk = new byte[1 << 16];
            Random.NextBytes(chunk);

            long memoryBefore = GC.GetTotalMemory(true);
            var stopwatch = Stopwatch.StartNew();

            var ciphertext = new MemoryStream();
            var encGen = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Aes256, true, Random);
            encGen.AddMethod(PgpMLKemX25519Test.MLKemSubkey(publicRing));
            using (Stream encOut = encGen.Open(ciphertext, new byte[1 << 16]))
            using (Stream litOut = new PgpLiteralDataGenerator().Open(encOut, PgpLiteralData.Binary, "", length,
                DateTime.UtcNow))
            {
                for (int written = 0; written < length; written += chunk.Length)
                {
                    litOut.Write(chunk, 0, chunk.Length);
                }
            }
            double encryptSeconds = stopwatch.Elapsed.TotalSeconds;

            stopwatch.Restart();
            ciphertext.Position = 0;
            var encList = (PgpEncryptedDataList)new PgpObjectFactory(ciphertext).NextPgpObject();
            var encData = (PgpPublicKeyEncryptedData)encList[0];
            var literal = (PgpLiteralData)new PgpObjectFactory(encData.GetDataStream(privateKey)).NextPgpObject();
            long read = 0;
            using (Stream data = literal.GetDataStream())
            {
                int n;
                while ((n = data.Read(chunk, 0, chunk.Length)) > 0)
                {
                    read += n;
                }
            }
            bool integrity = encData.Verify();
            double decryptSeconds = stopwatch.Elapsed.TotalSeconds;

            long overhead = GC.GetTotalMemory(false) - memoryBefore - ciphertext.Capacity;
            TestContext.WriteLine($"encrypt {length >> 20} MiB: {length / 1048576.0 / encryptSeconds:F1} MiB/s");
            TestContext.WriteLine($"decrypt {length >> 20} MiB: {length / 1048576.0 / decryptSeconds:F1} MiB/s");
            TestContext.WriteLine($"memory beyond the ciphertext buffer: {overhead / 1048576.0:F1} MiB");

            Assert.That(read, Is.EqualTo(length));
            Assert.That(integrity, Is.True);
            // Streaming: memory use must not grow with the payload
            Assert.That(overhead, Is.LessThan(16L * 1024 * 1024));
        }
    }
}
