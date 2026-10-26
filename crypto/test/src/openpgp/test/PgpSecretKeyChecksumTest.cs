using System;
using System.IO;

using NUnit.Framework;

using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Bcpg.OpenPgp.Tests
{
    /// <summary>
    /// Unprotected secret keys (S2K usage 0) must end with the 2-octet checksum of RFC 9580 5.5.3, even when the
    /// generator was asked for SHA-1 integrity checks (which only apply to encrypted keys).
    /// </summary>
    [TestFixture]
    public class PgpSecretKeyChecksumTest
    {
        private static readonly SecureRandom Random = new SecureRandom();

        [Test]
        public void UnprotectedKeyUsesTwoOctetChecksum()
        {
            var edGen = new Ed25519KeyPairGenerator();
            edGen.Init(new Ed25519KeyGenerationParameters(Random));
            var master = new PgpKeyPair(PublicKeyAlgorithmTag.EdDsa_Legacy, edGen.GenerateKeyPair(), DateTime.UtcNow);

            var xGen = new X25519KeyPairGenerator();
            xGen.Init(new X25519KeyGenerationParameters(Random));
            var sub = new PgpKeyPair(PublicKeyAlgorithmTag.ECDH, xGen.GenerateKeyPair(), DateTime.UtcNow);

            var krg = new PgpKeyRingGenerator(PgpSignature.PositiveCertification, master, "test",
                SymmetricKeyAlgorithmTag.Null, HashAlgorithmTag.Sha256, new char[0], useSha1: true, null, null,
                Random);
            krg.AddSubKey(sub, HashAlgorithmTag.Sha256);
            PgpSecretKeyRing ring = krg.GenerateSecretKeyRing();

            int checkedPackets = 0;
            var bcpgIn = BcpgInputStream.Wrap(new MemoryStream(ring.GetEncoded(), false));
            while (bcpgIn.NextPacketTag() >= 0)
            {
                if (bcpgIn.ReadPacket() is SecretKeyPacket secretPacket)
                {
                    Assert.That(secretPacket.S2kUsage, Is.EqualTo(SecretKeyPacket.UsageNone));

                    byte[] data = secretPacket.GetSecretKeyData();
                    int sum = 0;
                    for (int i = 0; i < data.Length - 2; ++i)
                    {
                        sum += data[i];
                    }
                    Assert.That(data[data.Length - 2], Is.EqualTo((byte)(sum >> 8)));
                    Assert.That(data[data.Length - 1], Is.EqualTo((byte)sum));
                    ++checkedPackets;
                }
            }
            Assert.That(checkedPackets, Is.EqualTo(2));

            var reparsed = new PgpSecretKeyRing(ring.GetEncoded());
            foreach (PgpSecretKey secretKey in reparsed.GetSecretKeys())
            {
                Assert.That(secretKey.ExtractPrivateKey(new char[0]), Is.Not.Null);
            }
        }
    }
}
