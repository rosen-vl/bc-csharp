using System;
using System.IO;
using System.Linq;
using System.Text;

using NUnit.Framework;

using Org.BouncyCastle.Crypto.Kems;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;

namespace Org.BouncyCastle.Bcpg.OpenPgp.Tests
{
    // The test vectors of RFC 9980 Appendix A.
    [TestFixture]
    public class PgpRfc9980VectorTest
    {
        /// <summary>The intermediate values that the RFC gives for the key encapsulation of a message.</summary>
        internal sealed class Kem
        {
            internal string Name;
            internal string MLKemShare;
            internal string EcdhShare;
            internal string Kek;
            internal string SessionKey;

            public override string ToString() => Name;
        }

        // RFC 9980 A.1.3, A.2.3, A.2.4, A.3.3, A.4.3 and A.5.3
        private static readonly Kem[] Kems =
        {
            new Kem
            {
                Name = "A.1.3",
                MLKemShare = "b0e45408d8c713f3941cd27276f879e557df013e05bcf43e37d4c60266a4b797",
                EcdhShare = "9d994741e0db5eacee44cb028c2ec48b1346feae2576aaac383bbcd64138c932",
                Kek = "5bf078bf7977109db6dead92d3578b62d0ab0487ef84e8e0af08f4b4b229e590",
                SessionKey = "94a3b8c9784463bb96b682cddf549adb23579b75bcb646f989d7cfe3e6e14435",
            },
            new Kem
            {
                Name = "A.2.3",
                MLKemShare = "16f2aea8ec1ca277c04cc7b87681d7d38511a38f554775a8fc4de41aa76eb586",
                EcdhShare = "2fc0c8fcace9636c86d1ee1715a302819ad48c549579a462a33eed36627c532e",
                Kek = "c1591d7511f9f0213bfd57cf316e5ec0d40c4ea826fa989ab606aa3b8a1a2c1f",
                SessionKey = "b4dc7197e1519822ca689da484643edf272934d98ae1974b5d88317a7a6a3c4f",
            },
            new Kem
            {
                Name = "A.2.4",
                MLKemShare = "16a22adbeced91ada60b5561611748edd2fedc51e0770f86d7394870062e7322",
                EcdhShare = "5ac67eab192f25ac99d87543e6fcd3a4769cb02c9d1afdc79354c2baa2289e29",
                Kek = "5c5652a690b55d1e9545fbd722f838cd8ff4d3657af5a9026d02f3185ca74993",
                SessionKey = "160867d96032b640208c1c92174d0270bb89189d72320711acd221bbea2a26b6",
            },
            new Kem
            {
                Name = "A.3.3",
                MLKemShare = "0987fe72ad5ea58e73344f9a2a543f4131d9fdb7cf07474f501430a20f705b4d",
                EcdhShare = "88f3e9a8de1917127b4b758f6e83bd4ce00faaae01bd8b6e412a43a710b26012",
                Kek = "a4904982f7caa9c9de690afd772d8bfe027a1ad6a5bbda00db68963fe303ae8e",
                SessionKey = "adee68618b302d4bfd7ae3d432bc63a1c1ad7f5fd6e7fd7bdedbb0d0b14a5c9a",
            },
            new Kem
            {
                Name = "A.4.3",
                MLKemShare = "f18f161e617b8ce5968f109aadea1e7e1511d10165768d36127ba913c00637d2",
                EcdhShare = "732860c8114ae84a964664b1f607785d11bc7d24d5324510adad89bd52db7ee0"
                    + "df9982ad0d1669bdd05556330c86f2dae9e2edea42e05bc5",
                Kek = "ef1e32906f67d39bc800d90cabb0033c77ca6dce8ffca3e96d9c7348e2e8c16e",
                SessionKey = "0588ce40b038aac353d1cf8c67a674b412985105794821013ef154f786c4d89d",
            },
            new Kem
            {
                Name = "A.5.3",
                MLKemShare = "5dc60150f5f965ddc8014b6aa2ecae1831467e98fa315422f238984d6421a22e",
                EcdhShare = "9dbd0f9bde7fef09817146e53a0b5ce7d27e79612670968fa0025422c578ab55",
                Kek = "ae8ab57801911c04c7b4c2a2f665cf8d8a8188f948c2a65e39c292d9b1d86e32",
                SessionKey = "e87567cad8fee5738f92090feed009d8af95437fa664f94da98776d966bbbc52",
            },
        };

        private sealed class Vector
        {
            internal Kem Kem;
            internal PgpPublicKeyRing PublicRing;
            internal PgpSecretKeyRing SecretRing;
            internal byte[] Message;
            internal PublicKeyAlgorithmTag Algorithm;
        }

        private static Vector LoadVector(string name, string kem, string messageFile, PublicKeyAlgorithmTag algorithm)
        {
            string prefix = name.Substring(0, 2);
            return new Vector
            {
                Kem = Kems.Single(k => k.Name == kem),
                PublicRing = new PgpPublicKeyRing(PgpV6TestUtilities.LoadRfc9980(prefix + "-public-key.asc")),
                SecretRing = new PgpSecretKeyRing(PgpV6TestUtilities.LoadRfc9980(prefix + "-secret-key.asc")),
                Message = PgpV6TestUtilities.LoadRfc9980(messageFile),
                Algorithm = algorithm,
            };
        }

        private static Vector[] Vectors() => new[]
        {
            LoadVector("a1", "A.1.3", "a1-message.asc", PublicKeyAlgorithmTag.MLKem768_X25519),
            new Vector
            {
                Kem = Kems.Single(k => k.Name == "A.2.3"),
                PublicRing = PgpMLKemX25519Test.A2PublicRing(),
                SecretRing = PgpMLKemX25519Test.A2SecretRing(),
                Message = PgpMLKemX25519Test.LoadA2("a2-seipdv1-message.asc"),
                Algorithm = PublicKeyAlgorithmTag.MLKem768_X25519,
            },
            new Vector
            {
                Kem = Kems.Single(k => k.Name == "A.2.4"),
                PublicRing = PgpMLKemX25519Test.A2PublicRing(),
                SecretRing = PgpMLKemX25519Test.A2SecretRing(),
                Message = PgpMLKemX25519Test.LoadA2("a2-seipdv2-message.asc"),
                Algorithm = PublicKeyAlgorithmTag.MLKem768_X25519,
            },
            LoadVector("a3", "A.3.3", "a3-message.asc", PublicKeyAlgorithmTag.MLKem768_X25519),
            LoadVector("a4", "A.4.3", "a4-message.asc", PublicKeyAlgorithmTag.MLKem1024_X448),
            LoadVector("a5", "A.5.3", "a5-message.asc", PublicKeyAlgorithmTag.MLKem768_X25519),
        };

        // The intermediate values of the composite KEM match the RFC.
        [Test]
        public void KemIntermediateValues()
        {
            foreach (Vector vector in Vectors())
            {
                PgpPrivateKey privateKey = vector.SecretRing.GetSecretKeys()
                    .First(k => k.PublicKey.Algorithm == vector.Algorithm).ExtractPrivateKey(new char[0]);
                var packet = (PublicKeyEncSessionPacket)BcpgInputStream.Wrap(new MemoryStream(vector.Message, false))
                    .ReadPacket();
                byte[] fields = packet.GetEncSessionKey()[0];

                byte[] ecdhPublicKey, ecdhShare = new byte[vector.Algorithm == PublicKeyAlgorithmTag.MLKem768_X25519
                    ? 32 : 56];
                byte[] mlKemShare = new byte[32];
                PgpCompositeKem kem = PgpCompositeKem.ForAlgorithm(vector.Algorithm);
                byte[] ecdhCipherText = Arrays.CopyOfRange(fields, 0, kem.EcdhCipherTextLength);
                byte[] mlKemCipherText = Arrays.CopyOfRange(fields, kem.EcdhCipherTextLength,
                    kem.EcdhCipherTextLength + kem.MLKemCipherTextLength);

                MLKemPrivateKeyParameters mlKemKey;
                if (vector.Algorithm == PublicKeyAlgorithmTag.MLKem768_X25519)
                {
                    var key = (MLKem768X25519PrivateKeyParameters)privateKey.Key;
                    key.X25519Key.GenerateSecret(new X25519PublicKeyParameters(ecdhCipherText), ecdhShare, 0);
                    ecdhPublicKey = ((MLKem768X25519PublicBcpgKey)privateKey.PublicKeyPacket.Key).GetX25519PublicKey();
                    mlKemKey = key.MLKemKey;
                }
                else
                {
                    var key = (MLKem1024X448PrivateKeyParameters)privateKey.Key;
                    key.X448Key.GenerateSecret(new X448PublicKeyParameters(ecdhCipherText), ecdhShare, 0);
                    ecdhPublicKey = ((MLKem1024X448PublicBcpgKey)privateKey.PublicKeyPacket.Key).GetX448PublicKey();
                    mlKemKey = key.MLKemKey;
                }

                var decapsulator = new MLKemDecapsulator(mlKemKey.Parameters);
                decapsulator.Init(mlKemKey);
                decapsulator.Decapsulate(mlKemCipherText, 0, mlKemCipherText.Length, mlKemShare, 0, 32);

                Assert.That(Hex.ToHexString(mlKemShare), Is.EqualTo(vector.Kem.MLKemShare), vector.Kem.Name);
                Assert.That(Hex.ToHexString(ecdhShare), Is.EqualTo(vector.Kem.EcdhShare), vector.Kem.Name);

                byte[] kek = kem.MultiKeyCombine(mlKemShare, ecdhShare, ecdhCipherText, ecdhPublicKey);
                Assert.That(Hex.ToHexString(kek), Is.EqualTo(vector.Kem.Kek), vector.Kem.Name);

                // the library does the same, and what it unwraps is the session key of the RFC
                Assert.That(Hex.ToHexString(kem.Decapsulate(
                    privateKey.Key is MLKem768X25519PrivateKeyParameters k768
                        ? (Org.BouncyCastle.Crypto.AsymmetricKeyParameter)k768.X25519Key
                        : ((MLKem1024X448PrivateKeyParameters)privateKey.Key).X448Key,
                    mlKemKey, ecdhPublicKey, ecdhCipherText, mlKemCipherText)), Is.EqualTo(vector.Kem.Kek));

                int lengthPos = kem.EcdhCipherTextLength + kem.MLKemCipherTextLength;
                int wrappedPos = lengthPos + 1 + (packet.Version == 3 ? 1 : 0);
                var wrapper = PgpUtilities.CreateWrapper(SymmetricKeyAlgorithmTag.Aes256);
                wrapper.Init(false, new Org.BouncyCastle.Crypto.Parameters.KeyParameter(kek));
                byte[] sessionKey = wrapper.Unwrap(fields, wrappedPos, fields.Length - wrappedPos);
                Assert.That(Hex.ToHexString(sessionKey), Is.EqualTo(vector.Kem.SessionKey), vector.Kem.Name);
            }
        }

        [Test]
        public void MessagesDecryptAndVerify()
        {
            foreach (Vector vector in Vectors())
            {
                PgpPrivateKey privateKey = vector.SecretRing.GetSecretKeys()
                    .First(k => k.PublicKey.Algorithm == vector.Algorithm).ExtractPrivateKey(new char[0]);

                PgpMLKemX25519Test.Decrypted result = PgpMLKemX25519Test.Decrypt(vector.Message, privateKey,
                    vector.PublicRing.GetPublicKey());

                Assert.That(Encoding.UTF8.GetString(result.Content), Is.EqualTo("Testing\n"), vector.Kem.Name);
                Assert.That(result.IntegrityVerified, Is.True, vector.Kem.Name);
                Assert.That(result.OnePassSignatureCount, Is.EqualTo(1), vector.Kem.Name);
                Assert.That(result.SignatureVerified, Is.True, vector.Kem.Name);
            }
        }

        private static readonly string[] CertificateVectors = { "a1", "a3", "a4", "a5", "a6", "a7" };

        [Test]
        public void SelfSignaturesVerify()
        {
            foreach (string vector in CertificateVectors)
            {
                var ring = new PgpPublicKeyRing(PgpV6TestUtilities.LoadRfc9980(vector + "-public-key.asc"));
                PgpPublicKey primary = ring.GetPublicKey();
                int count = 0;

                foreach (PgpSignature signature in primary.GetKeySignatures())
                {
                    signature.InitVerify(primary);
                    Assert.That(signature.VerifyCertification(primary), Is.True, vector + " direct key");
                    ++count;
                }

                foreach (string id in primary.GetUserIds())
                {
                    foreach (PgpSignature signature in primary.GetSignaturesForId(id))
                    {
                        signature.InitVerify(primary);
                        Assert.That(signature.VerifyCertification(id, primary), Is.True, vector + " " + id);
                        ++count;
                    }
                }

                foreach (PgpPublicKey subkey in ring.GetPublicKeys().Skip(1))
                {
                    foreach (PgpSignature binding in subkey.GetSignaturesOfType(PgpSignature.SubkeyBinding))
                    {
                        binding.InitVerify(primary);
                        Assert.That(binding.VerifyCertification(primary, subkey), Is.True, vector + " binding");
                        ++count;
                    }
                }

                Assert.That(count, Is.GreaterThanOrEqualTo(2), vector);
            }
        }

        // The key rings re-encode to the octets of the RFC.
        [Test]
        public void KeyRingsReEncodeExactly()
        {
            foreach (string vector in CertificateVectors)
            {
                byte[] publicEncoding = PgpV6TestUtilities.LoadRfc9980(vector + "-public-key.asc");
                byte[] secretEncoding = PgpV6TestUtilities.LoadRfc9980(vector + "-secret-key.asc");

                Assert.That(new PgpPublicKeyRing(publicEncoding).GetEncoded(), Is.EqualTo(publicEncoding), vector);
                Assert.That(new PgpSecretKeyRing(secretEncoding).GetEncoded(), Is.EqualTo(secretEncoding), vector);

                // and the public and the secret key ring agree
                PgpPublicKey[] fromPublic = new PgpPublicKeyRing(publicEncoding).GetPublicKeys().ToArray();
                PgpPublicKey[] fromSecret = new PgpSecretKeyRing(secretEncoding).GetPublicKeys().ToArray();
                Assert.That(fromPublic.Select(k => Hex.ToHexString(k.GetFingerprint())),
                    Is.EqualTo(fromSecret.Select(k => Hex.ToHexString(k.GetFingerprint()))), vector);
            }
        }

        [Test]
        public void SecretKeysMatchPublicKeys()
        {
            foreach (string vector in CertificateVectors)
            {
                var secretRing = new PgpSecretKeyRing(PgpV6TestUtilities.LoadRfc9980(vector + "-secret-key.asc"));
                foreach (PgpSecretKey secretKey in secretRing.GetSecretKeys())
                {
                    Assert.That(secretKey.IsPrivateKeyEmpty, Is.False);
                    PgpPrivateKey privateKey = secretKey.ExtractPrivateKey(new char[0]);
                    Assert.That(privateKey.KeyId, Is.EqualTo(secretKey.KeyId));
                    Assert.That(privateKey.Key, Is.Not.Null);
                }
            }
        }
    }
}
