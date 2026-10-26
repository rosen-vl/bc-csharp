using System;

using NUnit.Framework;

using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg.OpenPgp.Tests
{
    /// <summary>
    /// Tests for the key combiner of the composite KEMs of RFC 9980, algorithms 35 and 36: every input of the
    /// combiner is bound into the key-encryption key (RFC 9980 4.2.1, 9.2).
    /// </summary>
    [TestFixture]
    public class PgpCompositeKemTest
    {
        private static readonly SecureRandom Random = new SecureRandom();

        private static readonly byte[] Content = Strings.ToUtf8ByteArray("a message with two PKESKs for one key");

        private static readonly PublicKeyAlgorithmTag[] Algorithms =
        {
            PublicKeyAlgorithmTag.MLKem768_X25519, PublicKeyAlgorithmTag.MLKem1024_X448,
        };

        private static PgpKeyPair NewKeyPair(PublicKeyAlgorithmTag algorithm)
        {
            if (algorithm == PublicKeyAlgorithmTag.MLKem768_X25519)
            {
                var privateKey = new MLKem768X25519PrivateKeyParameters(Random);
                return new PgpKeyPair(6, algorithm, privateKey.GeneratePublicKey(), privateKey, DateTime.UtcNow);
            }
            else
            {
                var privateKey = new MLKem1024X448PrivateKeyParameters(Random);
                return new PgpKeyPair(6, algorithm, privateKey.GeneratePublicKey(), privateKey, DateTime.UtcNow);
            }
        }

        [Test]
        public void CombinerBindsEveryInput()
        {
            byte[] domainSeparator = Strings.ToUtf8ByteArray("OpenPGPCompositeKDFv1");

            foreach (var algorithm in Algorithms)
            {
                PgpCompositeKem kem = PgpCompositeKem.ForAlgorithm(algorithm);
                int ecdhLength = kem.EcdhCipherTextLength;

                // ML-KEM key share, ECDH key share, ECDH ciphertext, ECDH public key
                byte[][] inputs =
                {
                    SecureRandom.GetNextBytes(Random, 32), SecureRandom.GetNextBytes(Random, ecdhLength),
                    SecureRandom.GetNextBytes(Random, ecdhLength), SecureRandom.GetNextBytes(Random, ecdhLength),
                };
                byte[] kek = kem.MultiKeyCombine(inputs[0], inputs[1], inputs[2], inputs[3]);

                // the formula, computed independently
                var sha3 = new Sha3Digest(256);
                foreach (byte[] input in inputs)
                {
                    sha3.BlockUpdate(input, 0, input.Length);
                }
                sha3.Update((byte)algorithm);
                sha3.BlockUpdate(domainSeparator, 0, domainSeparator.Length);
                sha3.Update((byte)domainSeparator.Length);
                Assert.That(kek, Is.EqualTo(DigestUtilities.DoFinal(sha3)), algorithm.ToString());

                // a change of any bit of any input changes the key-encryption key
                for (int i = 0; i < inputs.Length; ++i)
                {
                    foreach (int bit in new[]{ 0, 7, 8 * inputs[i].Length - 1 })
                    {
                        byte[][] changed = (byte[][])inputs.Clone();
                        changed[i] = Arrays.Clone(inputs[i]);
                        changed[i][bit / 8] ^= (byte)(1 << (bit % 8));

                        Assert.That(kem.MultiKeyCombine(changed[0], changed[1], changed[2], changed[3]),
                            Is.Not.EqualTo(kek), algorithm + " input " + i + " bit " + bit);
                    }
                }

                // as does the algorithm ID
                byte otherId = (byte)(algorithm == PublicKeyAlgorithmTag.MLKem768_X25519
                    ? PublicKeyAlgorithmTag.MLKem1024_X448
                    : PublicKeyAlgorithmTag.MLKem768_X25519);
                Assert.That(PgpCompositeKem.MultiKeyCombine(inputs[0], inputs[1], inputs[2], inputs[3], otherId),
                    Is.Not.EqualTo(kek), algorithm.ToString());
            }
        }

        // RFC 9980 9.2: a PKESK made of the ECDH ciphertext of one encapsulation and the ML-KEM ciphertext of another
        // one does not decrypt, so neither key share can be replaced on its own
        [Test]
        public void CipherTextsOfTwoPkesksCannotBeCombined([Values(false, true)] bool aead)
        {
            foreach (var algorithm in Algorithms)
            {
                PgpKeyPair pair = NewKeyPair(algorithm);
                PgpCompositeKem kem = PgpCompositeKem.ForAlgorithm(algorithm);

                // two PKESKs for the same key: one session key, two encapsulations
                PgpPublicKey[] recipients = { pair.PublicKey, pair.PublicKey };
                byte[] message = aead
                    ? PgpV6PkeskTest.EncryptV2(recipients, Content)
                    : PgpMLKemX25519Test.Encrypt(recipients, Content);
                byte[][] packets = PgpUnsupportedVersionTest.SplitPackets(message);
                Assert.That(packets.Length, Is.EqualTo(3));

                var first = PgpV6TestUtilities.ReadPacket<PublicKeyEncSessionPacket>(packets[0]);
                var second = PgpV6TestUtilities.ReadPacket<PublicKeyEncSessionPacket>(packets[1]);
                byte[] fields1 = first.GetEncSessionKey()[0], fields2 = second.GetEncSessionKey()[0];

                byte[] WithPkesk(byte[] fields)
                {
                    PublicKeyEncSessionPacket pkesk = first.Version == PublicKeyEncSessionPacket.Version6
                        ? PublicKeyEncSessionPacket.CreateV6Packet(first.KeyVersion, first.GetKeyFingerprint(),
                            algorithm, new[]{ fields })
                        : PublicKeyEncSessionPacket.CreateV3Packet(first.KeyId, algorithm, new[]{ fields });
                    return Arrays.Concatenate(pkesk.GetEncoded(), packets[2]);
                }

                Assert.That(PgpMLKemX25519Test.Decrypt(WithPkesk(fields1), pair.PrivateKey).Content,
                    Is.EqualTo(Content));
                Assert.That(PgpMLKemX25519Test.Decrypt(WithPkesk(fields2), pair.PrivateKey).Content,
                    Is.EqualTo(Content));

                // ECDH ciphertext, ML-KEM ciphertext, and the rest with the wrapped session key
                int ecdhEnd = kem.EcdhCipherTextLength, mlKemEnd = ecdhEnd + kem.MLKemCipherTextLength;
                byte[] Mix(byte[] ecdhFrom, byte[] mlKemFrom, byte[] wrappedFrom) => Arrays.ConcatenateAll(
                    Arrays.CopyOfRange(ecdhFrom, 0, ecdhEnd), Arrays.CopyOfRange(mlKemFrom, ecdhEnd, mlKemEnd),
                    Arrays.CopyOfRange(wrappedFrom, mlKemEnd, wrappedFrom.Length));

                foreach (byte[] mixed in new[]
                {
                    Mix(fields1, fields2, fields1), Mix(fields1, fields2, fields2),
                    Mix(fields2, fields1, fields1), Mix(fields2, fields1, fields2),
                })
                {
                    var e = Assert.Throws<PgpException>(
                        () => PgpMLKemX25519Test.Decrypt(WithPkesk(mixed), pair.PrivateKey));
                    Assert.That(e.Message, Is.EqualTo("exception decrypting session key"), algorithm.ToString());
                }
            }
        }
    }
}
