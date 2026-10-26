using System;
using System.IO;
using System.Linq;

using NUnit.Framework;

using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Bcpg.OpenPgp.Tests
{
    /// <summary>
    /// The contract of the new public API under the ways applications actually use and misuse it: generator
    /// lifecycle, empty messages, the timing of <c>Verify</c>, behaviour after a failure, early disposal, argument
    /// validation, and an SLH-DSA signed and encrypted message end to end.
    /// </summary>
    [TestFixture]
    public class PgpV6ApiContractTest
    {
        private static readonly SecureRandom Random = new SecureRandom();

        private static readonly Lazy<PgpKeyPair> Recipient = new Lazy<PgpKeyPair>(() =>
        {
            var key = new MLKem768X25519PrivateKeyParameters(Random);
            return new PgpKeyPair(6, PublicKeyAlgorithmTag.MLKem768_X25519, key.GeneratePublicKey(), key,
                DateTime.UtcNow);
        });

        private static PgpEncryptedDataGenerator NewV2Generator(int chunkSizeOctet = 0)
        {
            var generator = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Aes256, AeadAlgorithmTag.Ocb,
                chunkSizeOctet, Random);
            generator.AddMethod(Recipient.Value.PublicKey);
            return generator;
        }

        private static byte[] Encrypt(byte[] content, int chunkSizeOctet = 0)
        {
            var output = new MemoryStream();
            using (Stream encOut = NewV2Generator(chunkSizeOctet).Open(output, new byte[256]))
            using (Stream litOut = new PgpLiteralDataGenerator().Open(encOut, PgpLiteralData.Binary, "",
                content.Length, DateTime.UtcNow))
            {
                litOut.Write(content, 0, content.Length);
            }
            return output.ToArray();
        }

        private static PgpPublicKeyEncryptedData Parse(byte[] message) =>
            (PgpPublicKeyEncryptedData)((PgpEncryptedDataList)new PgpObjectFactory(message).NextPgpObject())[0];

        [Test]
        public void GeneratorCannotBeOpenedTwiceAndCanBeReusedAfterClose()
        {
            PgpEncryptedDataGenerator generator = NewV2Generator();
            var first = new MemoryStream();
            Stream encOut = generator.Open(first, new byte[256]);
            Assert.Throws<InvalidOperationException>(() => generator.Open(new MemoryStream(), new byte[256]));
            encOut.Dispose();

            // after closing, the generator makes a new, independent message (new session key and salt)
            var second = new MemoryStream();
            using (generator.Open(second, new byte[256]))
            {
            }
            Assert.That(second.ToArray(), Is.Not.EqualTo(first.ToArray()));
            foreach (byte[] message in new[]{ first.ToArray(), second.ToArray() })
            {
                PgpPublicKeyEncryptedData encData = Parse(message);
                Assert.That(Streams.ReadAll(encData.GetDataStream(Recipient.Value.PrivateKey)), Is.Empty);
                Assert.That(encData.Verify(), Is.True);
            }
        }

        [Test]
        public void WritingAfterCloseFails()
        {
            Stream encOut = NewV2Generator().Open(new MemoryStream(), new byte[256]);
            encOut.Write(new byte[]{ 1, 2, 3 }, 0, 3);
            encOut.Dispose();
            Assert.Catch<Exception>(() => encOut.Write(new byte[]{ 4 }, 0, 1));
        }

        /// <summary>
        /// A definite-length message whose declared length does not match what is written is unusable.
        /// </summary>
        [Test]
        public void DefiniteLengthMustBeHonoured()
        {
            PgpEncryptedDataGenerator generator = NewV2Generator();
            var output = new MemoryStream();
            using (Stream encOut = generator.Open(output, 10))
            {
                encOut.Write(new byte[10], 0, 10);
            }
            PgpPublicKeyEncryptedData ok = Parse(output.ToArray());
            Assert.That(Streams.ReadAll(ok.GetDataStream(Recipient.Value.PrivateKey)).Length, Is.EqualTo(10));

            // fewer octets than declared: the packet claims more than it has, reading cannot succeed
            PgpEncryptedDataGenerator shortGenerator = NewV2Generator();
            var shortOutput = new MemoryStream();
            using (Stream encOut = shortGenerator.Open(shortOutput, 10))
            {
                encOut.Write(new byte[9], 0, 9);
            }
            Assert.Catch<Exception>(() =>
            {
                PgpPublicKeyEncryptedData encData = Parse(shortOutput.ToArray());
                Streams.ReadAll(encData.GetDataStream(Recipient.Value.PrivateKey));
                Assert.That(encData.Verify(), Is.True);
            });
        }

        /// <summary><c>Verify</c> before, during and after reading; it reads (and authenticates) the rest.</summary>
        [Test]
        public void VerifyAtAnyPoint([Values(0, 1, 100, 5000)] int readFirst)
        {
            byte[] content = SecureRandom.GetNextBytes(Random, 3000);
            PgpPublicKeyEncryptedData encData = Parse(Encrypt(content));
            Stream decrypted = encData.GetDataStream(Recipient.Value.PrivateKey);
            byte[] prefix = new byte[readFirst];
            int read = Streams.ReadFully(decrypted, prefix);
            Assert.That(read, Is.EqualTo(System.Math.Min(readFirst, 3 + 6 + 3000)),
                "the literal packet: header, fields, data");
            Assert.That(encData.Verify(), Is.True);
            Assert.That(encData.Verify(), Is.True, "Verify is idempotent");
        }

        /// <summary>
        /// After an authentication failure the stream stays failed, and Verify does not report success.
        /// </summary>
        [Test]
        public void FailureIsSticky()
        {
            byte[] content = SecureRandom.GetNextBytes(Random, 1000);
            byte[] message = Encrypt(content);
            message[message.Length - 40] ^= 1; // inside a chunk of the SEIPD packet

            PgpPublicKeyEncryptedData encData = Parse(message);
            Stream decrypted = encData.GetDataStream(Recipient.Value.PrivateKey);
            Assert.Throws<PgpDataValidationException>(() => Streams.ReadAll(decrypted));
            Assert.Throws<PgpDataValidationException>(() => decrypted.ReadByte());
            Assert.Throws<PgpDataValidationException>(() => decrypted.Read(new byte[10], 0, 10));
            bool verified;
            try
            {
                verified = encData.Verify();
            }
            catch (PgpException)
            {
                verified = false;
            }
            Assert.That(verified, Is.False);
        }

        /// <summary>Disposing a decryption stream before the end releases it without errors.</summary>
        [Test]
        public void EarlyDisposalIsHarmless()
        {
            byte[] content = SecureRandom.GetNextBytes(Random, 5000);
            PgpPublicKeyEncryptedData encData = Parse(Encrypt(content));
            Stream decrypted = encData.GetDataStream(Recipient.Value.PrivateKey);
            Assert.That(decrypted.ReadByte(), Is.Not.EqualTo(-1));
            Assert.DoesNotThrow(() => decrypted.Dispose());
            Assert.DoesNotThrow(() => decrypted.Dispose());
        }

        /// <summary>A message can be decrypted again from the same bytes; each parse is independent.</summary>
        [Test]
        public void RepeatedDecryptionOfTheSameBytes()
        {
            byte[] content = SecureRandom.GetNextBytes(Random, 2000);
            byte[] message = Encrypt(content, chunkSizeOctet: 1);
            for (int i = 0; i < 3; ++i)
            {
                PgpPublicKeyEncryptedData encData = Parse(message);
                var literal = (PgpLiteralData)new PgpObjectFactory(encData.GetDataStream(Recipient.Value.PrivateKey))
                    .NextPgpObject();
                Assert.That(Streams.ReadAll(literal.GetDataStream()), Is.EqualTo(content));
                Assert.That(encData.Verify(), Is.True);
            }
        }

        [Test]
        public void ArgumentValidation()
        {
            Assert.Throws<ArgumentNullException>(() => PgpEncryptionPreferences.Select(null));
            Assert.Throws<ArgumentException>(() => new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Aes128,
                (AeadAlgorithmTag)4, Random));
            Assert.Throws<ArgumentOutOfRangeException>(() => new PgpEncryptedDataGenerator(
                SymmetricKeyAlgorithmTag.Aes128, AeadAlgorithmTag.Ocb, -1, Random));
            Assert.Throws<ArgumentException>(() => new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Cast5,
                AeadAlgorithmTag.Ocb, Random));
            Assert.Catch<ArgumentException>(() => new PgpPublicKey(5, PublicKeyAlgorithmTag.Ed25519,
                Recipient.Value.PublicKey.GetKey(), DateTime.UtcNow));
            Assert.Catch<ArgumentException>(() => new PgpPublicKey(6, PublicKeyAlgorithmTag.Ed25519,
                Recipient.Value.PublicKey.GetKey(), DateTime.UtcNow), "parameters of another algorithm");
        }

        /// <summary>
        /// SLH-DSA-SHAKE-128f signing a compressed message that is encrypted with v2 SEIPD, and the same with v1:
        /// the 17,088-octet signature travels through compression, partial lengths and both encryption formats.
        /// </summary>
        [Test]
        public void SlhDsaSignedEncryptedMessage([Values(false, true)] bool aead)
        {
            PgpKeyPair signer = PgpSlhDsaTest.NewKeyPair(PublicKeyAlgorithmTag.SlhDsa_Shake128f);
            byte[] content = Strings.ToUtf8ByteArray(string.Concat(Enumerable.Repeat("SLH-DSA in OpenPGP\n", 500)));

            PgpEncryptedDataGenerator encGen = aead
                ? new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Aes256, AeadAlgorithmTag.Gcm, 1, Random)
                : new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Aes256, true, Random);
            encGen.AddMethod(Recipient.Value.PublicKey);

            var sGen = new PgpSignatureGenerator(PublicKeyAlgorithmTag.SlhDsa_Shake128f, HashAlgorithmTag.Sha3_256);
            sGen.InitSign(PgpSignature.CanonicalTextDocument, signer.PrivateKey, Random);

            var output = new MemoryStream();
            using (Stream encOut = encGen.Open(output, new byte[512]))
            {
                var compGen = new PgpCompressedDataGenerator(CompressionAlgorithmTag.ZLib);
                Stream compOut = compGen.Open(encOut, new byte[512]);
                sGen.GenerateOnePassVersion(false).Encode(compOut);
                using (Stream litOut = new PgpLiteralDataGenerator().Open(compOut, PgpLiteralData.Utf8, "",
                    DateTime.UtcNow, new byte[512]))
                {
                    litOut.Write(content, 0, content.Length);
                    sGen.Update(content);
                }
                PgpSignature signature = sGen.Generate();
                Assert.That(signature.GetSignature().Length, Is.EqualTo(17088));
                signature.Encode(compOut);
                compGen.Close();
            }

            PgpPublicKeyEncryptedData encData = Parse(output.ToArray());
            var factory = new PgpObjectFactory(encData.GetDataStream(Recipient.Value.PrivateKey));
            factory = new PgpObjectFactory(((PgpCompressedData)factory.NextPgpObject()).GetDataStream());
            PgpOnePassSignature ops = ((PgpOnePassSignatureList)factory.NextPgpObject())[0];
            ops.InitVerify(signer.PublicKey);
            byte[] received = Streams.ReadAll(((PgpLiteralData)factory.NextPgpObject()).GetDataStream());
            ops.Update(received);
            PgpSignature received6 = ((PgpSignatureList)factory.NextPgpObject())[0];
            Assert.That(received, Is.EqualTo(content));
            Assert.That(received6.Version, Is.EqualTo(6));
            Assert.That(ops.Verify(received6), Is.True);
            Assert.That(encData.Verify(), Is.True);
        }
    }
}
