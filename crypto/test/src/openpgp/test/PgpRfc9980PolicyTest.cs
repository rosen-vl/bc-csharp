using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

using NUnit.Framework;

using Org.BouncyCastle.Bcpg.Sig;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg.OpenPgp.Tests
{
    /// <summary>
    /// One test per row of the policy table for RFC 9980 (generation, parsing and use of the rules for versions, hash
    /// algorithms and message formats).
    /// </summary>
    [TestFixture]
    public class PgpRfc9980PolicyTest
    {
        private static readonly SecureRandom Random = new SecureRandom();

        private static readonly byte[] Data = Strings.ToUtf8ByteArray("policy test data");

        private static readonly PublicKeyAlgorithmTag[] Version6OnlyAlgorithms =
        {
            PublicKeyAlgorithmTag.MLDsa65_Ed25519, PublicKeyAlgorithmTag.MLDsa87_Ed448,
            PublicKeyAlgorithmTag.SlhDsa_Shake128s, PublicKeyAlgorithmTag.SlhDsa_Shake128f,
            PublicKeyAlgorithmTag.SlhDsa_Shake256s, PublicKeyAlgorithmTag.MLKem1024_X448,
        };

        private static readonly PublicKeyAlgorithmTag[] AllAlgorithms =
            Version6OnlyAlgorithms.Concat(new[]{ PublicKeyAlgorithmTag.MLKem768_X25519 }).ToArray();

        private static PgpKeyPair NewKeyPair(PublicKeyAlgorithmTag algorithm, int version)
        {
            switch (algorithm)
            {
            case PublicKeyAlgorithmTag.MLDsa65_Ed25519:
            case PublicKeyAlgorithmTag.MLDsa87_Ed448:
                return PgpMLDsaEdDsaTest.NewKeyPair(algorithm, version);
            case PublicKeyAlgorithmTag.SlhDsa_Shake128s:
            case PublicKeyAlgorithmTag.SlhDsa_Shake128f:
            case PublicKeyAlgorithmTag.SlhDsa_Shake256s:
                return PgpSlhDsaTest.NewKeyPair(algorithm, version);
            case PublicKeyAlgorithmTag.MLKem1024_X448:
            {
                var privateKey = new MLKem1024X448PrivateKeyParameters(Random);
                return new PgpKeyPair(version, algorithm, privateKey.GeneratePublicKey(), privateKey, DateTime.UtcNow);
            }
            case PublicKeyAlgorithmTag.MLKem768_X25519:
            {
                var privateKey = new MLKem768X25519PrivateKeyParameters(Random);
                return new PgpKeyPair(version, algorithm, privateKey.GeneratePublicKey(), privateKey, DateTime.UtcNow);
            }
            default:
                throw new ArgumentException("algorithm");
            }
        }

        private static PgpKeyPair EdDsaPair(int version)
        {
            var generator = new Ed25519KeyPairGenerator();
            generator.Init(new Ed25519KeyGenerationParameters(Random));
            return new PgpKeyPair(version, PublicKeyAlgorithmTag.Ed25519, generator.GenerateKeyPair(),
                DateTime.UtcNow);
        }

        [Test]
        public void NewAlgorithmsAreVersion6Only()
        {
            foreach (var algorithm in Version6OnlyAlgorithms)
            {
                PgpKeyPair version6 = NewKeyPair(algorithm, 6);
                Assert.That(version6.PublicKey.Version, Is.EqualTo(6), algorithm.ToString());
                Assert.That(version6.PublicKey.GetKey(), Is.Not.Null);

                Assert.Throws<ArgumentException>(() => NewKeyPair(algorithm, 4), algorithm.ToString());
                Assert.Throws<ArgumentException>(() =>
                    new PgpPublicKey(4, algorithm, version6.PublicKey.GetKey(), DateTime.UtcNow));
            }
        }

        [Test]
        public void MLKem768X25519IsAvailableForBothVersions()
        {
            foreach (int version in new[]{ 4, 6 })
            {
                PgpKeyPair pair = NewKeyPair(PublicKeyAlgorithmTag.MLKem768_X25519, version);
                Assert.That(pair.PublicKey.Version, Is.EqualTo(version));
                Assert.That(pair.PublicKey.GetKey(), Is.InstanceOf<MLKem768X25519PublicKeyParameters>());
            }
        }

        [Test]
        public void NewSignatureAlgorithmsNeedVersion6Signatures()
        {
            PgpKeyPair pair = NewKeyPair(PublicKeyAlgorithmTag.MLDsa65_Ed25519, 6);

            // generation: the key decides, so the signature is a version 6 signature
            var generator = new PgpSignatureGenerator(PublicKeyAlgorithmTag.MLDsa65_Ed25519, HashAlgorithmTag.Sha256);
            generator.InitSign(PgpSignature.BinaryDocument, pair.PrivateKey);
            generator.Update(Data);
            PgpSignature signature = generator.Generate();
            Assert.That(signature.Version, Is.EqualTo(6));

            // parsing: a version 4 signature packet for the algorithm is kept, with its raw signature
            var packet = new SignaturePacket(4, false, PgpSignature.BinaryDocument, 0x0102030405060708L,
                PublicKeyAlgorithmTag.MLDsa65_Ed25519, HashAlgorithmTag.Sha256, new SignatureSubpacket[0],
                new SignatureSubpacket[0], new byte[2], null, null, signature.GetSignature());
            var version4 = new PgpSignature(packet);
            Assert.That(version4.Version, Is.EqualTo(4));
            Assert.That(version4.KeyAlgorithm, Is.EqualTo(PublicKeyAlgorithmTag.MLDsa65_Ed25519));

            // use: it never verifies
            version4.InitVerify(pair.PublicKey);
            version4.Update(Data);
            Assert.That(version4.Verify(), Is.False);
        }

        // RFC 9980 3.5: algorithm 35 is allowed in version 4 subkeys, but not in version 4 primary keys
        [Test]
        public void MLKem768X25519IsOnlyASubkeyInVersion4Keys()
        {
            byte[] body = NewKeyPair(PublicKeyAlgorithmTag.MLKem768_X25519, 4).PublicKey.PublicKeyPacket
                .GetEncodedContents();

            var subkey = PgpV6TestUtilities.ReadPacket<PublicKeyPacket>(
                PgpV6TestUtilities.NewFormatPacket(PacketTag.PublicSubkey, body));
            Assert.That(subkey.Key, Is.InstanceOf<MLKem768X25519PublicBcpgKey>());

            var primary = PgpV6TestUtilities.ReadPacket<PublicKeyPacket>(
                PgpV6TestUtilities.NewFormatPacket(PacketTag.PublicKey, body));
            Assert.That(primary.Key, Is.InstanceOf<UnknownBcpgKey>());
            var generator = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Aes256, true, Random);
            Assert.Throws<ArgumentException>(() => generator.AddMethod(new PgpPublicKey(primary)));

            // the secret key material of a version 4 key has no length, so such a secret primary key cannot be read
            byte[] secretBody = Arrays.Concatenate(body, new byte[1 + MLKem768X25519SecretBcpgKey.Length + 2]);
            Assert.That(PgpV6TestUtilities.ReadPacket<SecretSubkeyPacket>(PgpV6TestUtilities.NewFormatPacket(
                PacketTag.SecretSubkey, secretBody)).PublicKeyPacket.Key, Is.InstanceOf<MLKem768X25519PublicBcpgKey>());
            Assert.Throws<MalformedPacketException>(() => PgpV6TestUtilities.ReadPacket<SecretKeyPacket>(
                PgpV6TestUtilities.NewFormatPacket(PacketTag.SecretKey, secretBody)));
        }

        // Key material that is not defined for the version of its key is kept opaque, and cannot be encrypted to
        [Test]
        public void OpaqueKeysAreRefusedAsRecipients()
        {
            byte[] material = ((MLKem1024X448PublicBcpgKey)NewKeyPair(PublicKeyAlgorithmTag.MLKem1024_X448, 6)
                .PublicKey.PublicKeyPacket.Key).GetKey();
            byte[] body = Arrays.Concatenate(
                new byte[]{ 4, 0, 0, 0, 1, (byte)PublicKeyAlgorithmTag.MLKem1024_X448 }, material);

            var packet = PgpV6TestUtilities.ReadPacket<PublicKeyPacket>(
                PgpV6TestUtilities.NewFormatPacket(PacketTag.PublicSubkey, body));
            Assert.That(packet.Key, Is.InstanceOf<UnknownBcpgKey>());
            var key = new PgpPublicKey(packet);
            Assert.That(key.IsEncryptionKey, Is.True);

            foreach (var generator in new[]
            {
                new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Aes256, true, Random),
                new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Aes256, AeadAlgorithmTag.Ocb, Random),
            })
            {
                Assert.Throws<ArgumentException>(() => generator.AddMethod(key));
            }
        }

        // RFC 9580 10.1.1 and 10.1.3: the subkeys of a key have the version of the primary key
        [Test]
        public void BindingsNeedSubkeysOfTheirVersion()
        {
            PgpKeyPair primary = EdDsaPair(6);
            PgpPublicKey v4Subkey = NewKeyPair(PublicKeyAlgorithmTag.MLKem768_X25519, 4).PublicKey;
            PgpPublicKey v6Subkey = NewKeyPair(PublicKeyAlgorithmTag.MLKem768_X25519, 6).PublicKey;

            PgpSignatureGenerator Generator(PgpKeyPair signer)
            {
                var generator = new PgpSignatureGenerator(PublicKeyAlgorithmTag.Ed25519, HashAlgorithmTag.Sha256);
                generator.InitSign(PgpSignature.SubkeyBinding, signer.PrivateKey);
                return generator;
            }

            bool Verify(PgpSignature binding, PgpPublicKey subkey)
            {
                binding.InitVerify(primary.PublicKey);
                return binding.VerifyCertification(primary.PublicKey, subkey);
            }

            Assert.That(Verify(Generator(primary).GenerateCertification(primary.PublicKey, v6Subkey), v6Subkey),
                Is.True);
            Assert.Throws<PgpException>(() => Generator(primary).GenerateCertification(primary.PublicKey, v4Subkey));

            // a binding of the version 4 subkey made all the same does not verify, unlike one of the version 6 one
            foreach (PgpPublicKey subkey in new[]{ v4Subkey, v6Subkey })
            {
                PgpSignatureGenerator generator = Generator(primary);
                PgpMLKemX25519Test.UpdateWithKey(generator, primary.PublicKey, signatureVersion: 6);
                PgpMLKemX25519Test.UpdateWithKey(generator, subkey, signatureVersion: 6);
                Assert.That(Verify(generator.Generate(), subkey), Is.EqualTo(subkey == v6Subkey));
            }

            PgpKeyPair v4Primary = EdDsaPair(4);
            Assert.Throws<PgpException>(() => Generator(v4Primary).GenerateCertification(v4Primary.PublicKey,
                v6Subkey));
        }

        // A one-pass signature announces the hash and the algorithm of its signature
        [Test]
        public void OnePassSignaturesMatchTheirSignatures()
        {
            foreach (int version in new[]{ 4, 6 })
            {
                PgpKeyPair pair = EdDsaPair(version);
                var generator = new PgpSignatureGenerator(PublicKeyAlgorithmTag.Ed25519, HashAlgorithmTag.Sha256);
                generator.InitSign(PgpSignature.BinaryDocument, pair.PrivateKey);
                generator.Update(Data);
                PgpSignature signature = generator.Generate();

                // SHA3-256 has the salt size of SHA-256
                foreach (var hash in new[]{ HashAlgorithmTag.Sha256, HashAlgorithmTag.Sha3_256 })
                {
                    var onePass = new PgpOnePassSignature(version == 6
                        ? new OnePassSignaturePacket(PgpSignature.BinaryDocument, hash, PublicKeyAlgorithmTag.Ed25519,
                            signature.GetSalt(), pair.PublicKey.GetFingerprint(), false)
                        : new OnePassSignaturePacket(PgpSignature.BinaryDocument, hash, PublicKeyAlgorithmTag.Ed25519,
                            pair.KeyId, false));
                    onePass.InitVerify(pair.PublicKey);
                    onePass.Update(Data);
                    Assert.That(onePass.Verify(signature), Is.EqualTo(hash == HashAlgorithmTag.Sha256),
                        version + " " + hash);
                }
            }

            // the two algorithm IDs of RSA signing keys sign alike
            var rsa = new PgpKeyPair(PublicKeyAlgorithmTag.RsaGeneral, PgpV6KeyGenerationTest.GenerateRsa(),
                DateTime.UtcNow);
            var rsaGenerator = new PgpSignatureGenerator(PublicKeyAlgorithmTag.RsaGeneral, HashAlgorithmTag.Sha256);
            rsaGenerator.InitSign(PgpSignature.BinaryDocument, rsa.PrivateKey);
            rsaGenerator.Update(Data);
            PgpSignature rsaSignature = rsaGenerator.Generate();

            var rsaOnePass = new PgpOnePassSignature(new OnePassSignaturePacket(PgpSignature.BinaryDocument,
                HashAlgorithmTag.Sha256, PublicKeyAlgorithmTag.RsaSign, rsa.KeyId, false));
            rsaOnePass.InitVerify(rsa.PublicKey);
            rsaOnePass.Update(Data);
            Assert.That(rsaOnePass.Verify(rsaSignature), Is.True);
        }

        [Test]
        public void SignatureVersionFollowsKeyVersion()
        {
            PgpKeyPair version6 = EdDsaPair(6);
            PgpKeyPair version4 = EdDsaPair(4);

            PgpSignature SignWith(PgpKeyPair pair)
            {
                var generator = new PgpSignatureGenerator(PublicKeyAlgorithmTag.Ed25519, HashAlgorithmTag.Sha256);
                generator.InitSign(PgpSignature.BinaryDocument, pair.PrivateKey);
                generator.Update(Data);
                return generator.Generate();
            }

            bool Verify(PgpSignature signature, PgpPublicKey key)
            {
                signature.InitVerify(key);
                signature.Update(Data);
                return signature.Verify();
            }

            PgpSignature signature6 = SignWith(version6);
            PgpSignature signature4 = SignWith(version4);
            Assert.That(signature6.Version, Is.EqualTo(6));
            Assert.That(signature4.Version, Is.EqualTo(4));
            Assert.That(Verify(signature6, version6.PublicKey), Is.True);
            Assert.That(Verify(signature4, version4.PublicKey), Is.True);

            // the same key material in the other version of key
            var asVersion4 = new PgpPublicKey(4, PublicKeyAlgorithmTag.Ed25519, version6.PublicKey.GetKey(),
                version6.PublicKey.CreationTime);
            var asVersion6 = new PgpPublicKey(6, PublicKeyAlgorithmTag.Ed25519, version4.PublicKey.GetKey(),
                version4.PublicKey.CreationTime);
            Assert.That(Verify(signature6, asVersion4), Is.False);
            Assert.That(Verify(signature4, asVersion6), Is.False);
        }

        [Test]
        public void SignatureHashesNeedAtLeast256Bits()
        {
            foreach (var algorithm in new[]
            {
                PublicKeyAlgorithmTag.MLDsa65_Ed25519, PublicKeyAlgorithmTag.MLDsa87_Ed448,
                PublicKeyAlgorithmTag.SlhDsa_Shake128f,
            })
            {
                PgpKeyPair pair = NewKeyPair(algorithm, 6);

                foreach (var hash in new[]
                {
                    HashAlgorithmTag.Sha1, HashAlgorithmTag.Sha224, HashAlgorithmTag.RipeMD160,
                })
                {
                    var generator = new PgpSignatureGenerator(algorithm, hash);
                    Assert.Throws<PgpException>(() => generator.InitSign(PgpSignature.BinaryDocument, pair.PrivateKey),
                        algorithm + " " + hash);
                    Assert.That(PgpUtilities.IsHashStrongEnough(algorithm, hash), Is.False);
                }

                foreach (var hash in new[]
                {
                    HashAlgorithmTag.Sha256, HashAlgorithmTag.Sha384, HashAlgorithmTag.Sha512,
                    HashAlgorithmTag.Sha3_256, HashAlgorithmTag.Sha3_512,
                })
                {
                    Assert.That(PgpUtilities.IsHashStrongEnough(algorithm, hash), Is.True);
                }
            }

            foreach (var algorithm in new[]
            {
                PublicKeyAlgorithmTag.SlhDsa_Shake128s, PublicKeyAlgorithmTag.SlhDsa_Shake256s,
            })
            {
                Assert.That(PgpUtilities.IsHashStrongEnough(algorithm, HashAlgorithmTag.Sha224), Is.False);
                Assert.That(PgpUtilities.IsHashStrongEnough(algorithm, HashAlgorithmTag.Sha256), Is.True);
            }
        }

        private static ISigner RawSigner(PublicKeyAlgorithmTag algorithm) => PgpUtilities.IsSlhDsaAlgorithm(algorithm)
            ? (ISigner)new SlhDsaSigner(PgpUtilities.GetSlhDsaParameters(algorithm), deterministic: false)
            : new PgpCompositeSigner(algorithm);

        // A version 6 signature over Data whose digest is signed with the signer of the algorithm itself, so that it
        // can use a hash that the signature generator refuses
        private static PgpSignature SignDigestDirectly(PgpKeyPair pair, HashAlgorithmTag hash, out bool valueVerifies)
        {
            PublicKeyAlgorithmTag algorithm = pair.PublicKey.Algorithm;
            SignatureSubpacket[] hashed =
            {
                new SignatureCreationTime(false, DateTime.UtcNow),
                new IssuerFingerprint(false, PublicKeyPacket.Version6, pair.PublicKey.GetFingerprint()),
            };
            var unhashed = new SignatureSubpacket[0];
            byte[] salt = SecureRandom.GetNextBytes(Random, PgpUtilities.GetV6SaltSize(hash));

            // the trailer does not depend on the signature value
            byte[] trailer = new SignaturePacket(6, true, PgpSignature.BinaryDocument, pair.KeyId, algorithm, hash,
                hashed, unhashed, new byte[2], salt, null, new byte[0]).GetSignatureTrailer();
            IDigest digest = PgpUtilities.CreateDigest(hash);
            digest.BlockUpdate(salt, 0, salt.Length);
            digest.BlockUpdate(Data, 0, Data.Length);
            digest.BlockUpdate(trailer, 0, trailer.Length);
            byte[] hashValue = DigestUtilities.DoFinal(digest);

            ISigner signer = RawSigner(algorithm);
            signer.Init(true, new ParametersWithRandom(pair.PrivateKey.Key, Random));
            signer.BlockUpdate(hashValue, 0, hashValue.Length);
            byte[] value = signer.GenerateSignature();

            ISigner verifier = RawSigner(algorithm);
            verifier.Init(false, pair.PublicKey.GetKey());
            verifier.BlockUpdate(hashValue, 0, hashValue.Length);
            valueVerifies = verifier.VerifySignature(value);

            return new PgpSignature(new SignaturePacket(6, true, PgpSignature.BinaryDocument, pair.KeyId, algorithm,
                hash, hashed, unhashed, new byte[]{ hashValue[0], hashValue[1] }, salt, null, value));
        }

        // RFC 9980 5.3.1 and 6.2.1: verifiers reject digests of less than 256 bits, even under a valid signature value.
        // SHA-224 has the salt size of SHA-256, so nothing but the size of the digest is wrong.
        [TestCase(PublicKeyAlgorithmTag.MLDsa65_Ed25519)]
        [TestCase(PublicKeyAlgorithmTag.MLDsa87_Ed448)]
        [TestCase(PublicKeyAlgorithmTag.SlhDsa_Shake128f)]
        public void ValidSignaturesWithShortDigestsAreRejected(PublicKeyAlgorithmTag algorithm)
        {
            PgpKeyPair pair = CheckShortDigestIsRejected(algorithm);

            // the same construction with SHA-256 verifies
            PgpSignature signature = SignDigestDirectly(pair, HashAlgorithmTag.Sha256, out bool valueVerifies);
            Assert.That(valueVerifies, Is.True);
            signature.InitVerify(pair.PublicKey);
            signature.Update(Data);
            Assert.That(signature.Verify(), Is.True);
        }

        // As above, for the parameter sets of SLH-DSA whose signatures take most of a minute to make
        [Explicit, TestCase(PublicKeyAlgorithmTag.SlhDsa_Shake128s), TestCase(PublicKeyAlgorithmTag.SlhDsa_Shake256s)]
        public void ValidSlowSignaturesWithShortDigestsAreRejected(PublicKeyAlgorithmTag algorithm) =>
            CheckShortDigestIsRejected(algorithm);

        private static PgpKeyPair CheckShortDigestIsRejected(PublicKeyAlgorithmTag algorithm)
        {
            PgpKeyPair pair = NewKeyPair(algorithm, 6);

            PgpSignature signature = SignDigestDirectly(pair, HashAlgorithmTag.Sha224, out bool valueVerifies);
            Assert.That(valueVerifies, Is.True);
            signature.InitVerify(pair.PublicKey);
            signature.Update(Data);
            Assert.That(signature.Verify(), Is.False);

            var onePass = new PgpOnePassSignature(new OnePassSignaturePacket(PgpSignature.BinaryDocument,
                HashAlgorithmTag.Sha224, algorithm, signature.GetSalt(), pair.PublicKey.GetFingerprint(), false));
            onePass.InitVerify(pair.PublicKey);
            onePass.Update(Data);
            Assert.That(onePass.Verify(signature), Is.False);

            return pair;
        }

        [Test]
        public void BindingSignaturesRefuseWeakHashes()
        {
            var generator = new PgpKeyRingGenerator(EdDsaPair(6), HashAlgorithmTag.Sha256, null, null,
                PgpSecretKeyProtection.None, Random);

            foreach (var algorithm in AllAlgorithms)
            {
                PgpKeyPair subkey = NewKeyPair(algorithm, 6);
                foreach (var hash in new[]{ HashAlgorithmTag.MD5, HashAlgorithmTag.Sha1, HashAlgorithmTag.RipeMD160 })
                {
                    Assert.Throws<ArgumentException>(() => generator.AddSubKey(subkey, null, null, hash),
                        algorithm + " " + hash);
                }

                generator.AddSubKey(subkey, null, null, HashAlgorithmTag.Sha256);
            }

            PgpPublicKeyRing ring = generator.GeneratePublicKeyRing();
            PgpPublicKey primary = ring.GetPublicKey();
            foreach (PgpPublicKey subkey in ring.GetPublicKeys().Skip(1))
            {
                PgpSignature binding = subkey.GetSignaturesOfType(PgpSignature.SubkeyBinding)
                    .Cast<PgpSignature>().Single();
                binding.InitVerify(primary);
                Assert.That(binding.VerifyCertification(primary, subkey), Is.True, subkey.Algorithm.ToString());
            }

            // the default hash of the classic generator is not SHA-1 for these keys
            var classic = new PgpKeyRingGenerator(PgpSignature.PositiveCertification, EdDsaPair(6), "id",
                SymmetricKeyAlgorithmTag.Null, HashAlgorithmTag.Sha256, new char[0], true, null, null, Random);
            classic.AddSubKey(NewKeyPair(PublicKeyAlgorithmTag.MLKem1024_X448, 6));
            PgpPublicKey classicSubkey = classic.GeneratePublicKeyRing().GetPublicKeys().Last();
            Assert.That(classicSubkey.GetSignaturesOfType(PgpSignature.SubkeyBinding)
                .Cast<PgpSignature>().Single().HashAlgorithm, Is.Not.EqualTo(HashAlgorithmTag.Sha1));
        }

        [Test]
        public void Version3PkeskNeedsAes()
        {
            var recipients = new List<PgpPublicKey>
            {
                PgpXdhEncryptionTest.NewSubkeyPair(PublicKeyAlgorithmTag.X25519).PublicKey,
                PgpXdhEncryptionTest.NewSubkeyPair(PublicKeyAlgorithmTag.X448).PublicKey,
                NewKeyPair(PublicKeyAlgorithmTag.MLKem768_X25519, 4).PublicKey,
                NewKeyPair(PublicKeyAlgorithmTag.MLKem1024_X448, 6).PublicKey,
            };

            foreach (PgpPublicKey recipient in recipients)
            {
                foreach (var cipher in new[]
                {
                    SymmetricKeyAlgorithmTag.TripleDes, SymmetricKeyAlgorithmTag.Blowfish,
                    SymmetricKeyAlgorithmTag.Camellia256, SymmetricKeyAlgorithmTag.Twofish,
                })
                {
                    var generator = new PgpEncryptedDataGenerator(cipher, true, Random);
                    Assert.Throws<PgpException>(() => generator.AddMethod(recipient),
                        recipient.Algorithm + " " + cipher);
                }

                // and the obsolete packet without integrity protection is refused
                var withoutIntegrity = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Aes256, false, Random);
                Assert.Throws<PgpException>(() => withoutIntegrity.AddMethod(recipient),
                    recipient.Algorithm.ToString());

                foreach (var cipher in new[]
                {
                    SymmetricKeyAlgorithmTag.Aes128, SymmetricKeyAlgorithmTag.Aes192, SymmetricKeyAlgorithmTag.Aes256,
                })
                {
                    var generator = new PgpEncryptedDataGenerator(cipher, true, Random);
                    Assert.DoesNotThrow(() => generator.AddMethod(recipient));
                }
            }
        }

        [Test]
        public void EskVersionsAlignWithThePayload()
        {
            PgpKeyPair recipient = NewKeyPair(PublicKeyAlgorithmTag.MLKem1024_X448, 6);
            byte[] version1 = PgpMLKemX25519Test.Encrypt(new[]{ recipient.PublicKey }, Data);
            byte[] version2 = PgpV6PkeskTest.EncryptV2(new[]{ recipient.PublicKey }, Data);

            byte[][] v1Packets = PgpUnsupportedVersionTest.SplitPackets(version1);
            byte[][] v2Packets = PgpUnsupportedVersionTest.SplitPackets(version2);
            Assert.That(v1Packets.Length, Is.EqualTo(2));
            Assert.That(v2Packets.Length, Is.EqualTo(2));

            // the version 3 PKESK, then a version 2 SEIPD, and the other way round
            foreach (byte[] mismatched in new[]
            {
                Arrays.Concatenate(v1Packets[0], v2Packets[1]), Arrays.Concatenate(v2Packets[0], v1Packets[1]),
            })
            {
                var list = (PgpEncryptedDataList)new PgpObjectFactory(mismatched).NextPgpObject();
                Assert.That(list.Count, Is.EqualTo(0));
            }

            // aligned messages still work
            Assert.That(((PgpEncryptedDataList)new PgpObjectFactory(version1).NextPgpObject()).Count, Is.EqualTo(1));
            Assert.That(((PgpEncryptedDataList)new PgpObjectFactory(version2).NextPgpObject()).Count, Is.EqualTo(1));
        }

        [Test]
        public void LegacyAlgorithmsAreNotAvailableInVersion6()
        {
            var edGenerator = new Ed25519KeyPairGenerator();
            edGenerator.Init(new Ed25519KeyGenerationParameters(Random));
            Assert.Throws<ArgumentException>(() => new PgpKeyPair(6, PublicKeyAlgorithmTag.EdDsa_Legacy,
                edGenerator.GenerateKeyPair(), DateTime.UtcNow));

            var xGenerator = new X25519KeyPairGenerator();
            xGenerator.Init(new X25519KeyGenerationParameters(Random));
            Assert.Throws<ArgumentException>(() => new PgpKeyPair(6, PublicKeyAlgorithmTag.ECDH,
                xGenerator.GenerateKeyPair(), DateTime.UtcNow));
        }

        [Test]
        public void ChunkSizeOctetIsLimited()
        {
            foreach (int octet in new[]{ -1, 17, 18, 255, 256 })
            {
                Assert.Catch<ArgumentException>(() => new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Aes256,
                    AeadAlgorithmTag.Ocb, octet, Random), "" + octet);
            }

            foreach (int octet in new[]{ 0, 6, 16 })
            {
                Assert.DoesNotThrow(() => new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Aes256,
                    AeadAlgorithmTag.Ocb, octet, Random), "" + octet);
            }
        }

        [Test]
        public void SignatureType0xFFIsRefused()
        {
            PgpKeyPair pair = EdDsaPair(6);
            var generator = new PgpSignatureGenerator(PublicKeyAlgorithmTag.Ed25519, HashAlgorithmTag.Sha256);
            Assert.Throws<ArgumentException>(() => generator.InitSign(0xFF, pair.PrivateKey));
        }

        [Test]
        public void WeakS2kHashesAreRefused()
        {
            // RFC 9580 9.5: no new S2K with MD5, SHA-1 or RIPEMD-160, whatever the version of the key
            foreach (var hash in new[]{ HashAlgorithmTag.MD5, HashAlgorithmTag.Sha1, HashAlgorithmTag.RipeMD160 })
            {
                Assert.Throws<ArgumentException>(() => PgpSecretKeyProtection.AeadIterated(
                    SymmetricKeyAlgorithmTag.Aes256, AeadAlgorithmTag.Ocb, hash, 0x60, Data), hash.ToString());
                Assert.Throws<ArgumentException>(() => PgpSecretKeyProtection.Cfb(SymmetricKeyAlgorithmTag.Aes256,
                    hash, 0x60, Data), hash.ToString());
            }
        }

        [Test]
        public void UnknownAlgorithmsAreOpaque()
        {
            foreach (int algorithm in new[]{ 37, 40, 44, 99 })
            {
                // version 6 body: version, time, algorithm, key material length, key material
                byte[] key = new byte[100];
                byte[] body = Arrays.ConcatenateAll(
                    new byte[]{ 6, 0, 0, 0, 1, (byte)algorithm, 0, 0, 0, (byte)key.Length }, key);

                var packet = PgpV6TestUtilities.ReadPacket<PublicKeyPacket>(
                    PgpV6TestUtilities.NewFormatPacket(PacketTag.PublicKey, body));
                var publicKey = new PgpPublicKey(packet);

                Assert.That((int)publicKey.Algorithm, Is.EqualTo(algorithm));
                Assert.That(publicKey.Version, Is.EqualTo(6));
                Assert.That(publicKey.GetFingerprint().Length, Is.EqualTo(32));
                Assert.Throws<PgpException>(() => publicKey.GetKey(), "algorithm " + algorithm);
            }
        }

        [Test]
        public void CompositeKemAlgorithmsAreNotSigningAlgorithms()
        {
            var generator = new PgpKeyRingGenerator(EdDsaPair(6), HashAlgorithmTag.Sha256, null, null,
                PgpSecretKeyProtection.None, Random);

            foreach (var algorithm in new[]
            {
                PublicKeyAlgorithmTag.MLKem1024_X448, PublicKeyAlgorithmTag.MLKem768_X25519,
            })
            {
                PgpKeyPair pair = NewKeyPair(algorithm, 6);
                Assert.That(pair.PublicKey.IsEncryptionKey, Is.True);

                // not as the primary key, and not with a primary key binding
                Assert.Throws<ArgumentException>(() => new PgpKeyRingGenerator(pair, HashAlgorithmTag.Sha256, null,
                    null, PgpSecretKeyProtection.None, Random));
                Assert.Throws<ArgumentException>(() => generator.AddSubKey(pair, null, null, HashAlgorithmTag.Sha256,
                    HashAlgorithmTag.Sha256));

                // and not for signing
                var signer = new PgpSignatureGenerator(algorithm, HashAlgorithmTag.Sha256);
                Assert.Throws<PgpException>(() => signer.InitSign(PgpSignature.BinaryDocument, pair.PrivateKey));
            }
        }
    }
}
