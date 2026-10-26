using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Bcpg.Sig;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;

namespace Org.BouncyCastle.Tools.PgpInterop
{
    internal static partial class Program
    {
        /// <summary>A kind of key that <c>generate-key</c> makes.</summary>
        private sealed class KeyProfile
        {
            internal string Name;
            internal string Alias;
            internal string Description;
            internal int Version;
            internal PublicKeyAlgorithmTag PrimaryAlgorithm;
            internal PublicKeyAlgorithmTag SubkeyAlgorithm;

            /// <summary>A second encryption subkey (a profile for tests of the recipient selection).</summary>
            internal PublicKeyAlgorithmTag? ExtraSubkeyAlgorithm;

            /// <summary>No encryption subkey at all (a profile for tests).</summary>
            internal bool SigningOnly;

            /// <summary>The AEAD mode that the preferences of a version 6 key put first, with AES-256.</summary>
            internal AeadAlgorithmTag Aead = AeadAlgorithmTag.Ocb;

            internal HashAlgorithmTag Hash;
        }

        private static readonly KeyProfile[] KeyProfiles =
        {
            new KeyProfile
            {
                Name = "rfc9980-v4", Alias = "default", Version = 4,
                Description = "v4 key, Ed25519 (legacy) primary key and ML-KEM-768+X25519 subkey",
                PrimaryAlgorithm = PublicKeyAlgorithmTag.EdDsa_Legacy,
                SubkeyAlgorithm = PublicKeyAlgorithmTag.MLKem768_X25519, Hash = HashAlgorithmTag.Sha512,
            },
            new KeyProfile
            {
                Name = "rfc4880", Version = 4,
                Description = "v4 key, Ed25519 (legacy) primary key and Curve25519 ECDH subkey",
                PrimaryAlgorithm = PublicKeyAlgorithmTag.EdDsa_Legacy, SubkeyAlgorithm = PublicKeyAlgorithmTag.ECDH,
                Hash = HashAlgorithmTag.Sha512,
            },
            new KeyProfile
            {
                Name = "rfc9580", Version = 6, Description = "v6 key, Ed25519 primary key and X25519 subkey",
                PrimaryAlgorithm = PublicKeyAlgorithmTag.Ed25519, SubkeyAlgorithm = PublicKeyAlgorithmTag.X25519,
                Hash = HashAlgorithmTag.Sha512,
            },
            new KeyProfile
            {
                Name = "rfc9580-mixed", Version = 6,
                Description = "v6 key, Ed25519 primary key, X25519 and ML-KEM-768+X25519 subkeys (for tests)",
                PrimaryAlgorithm = PublicKeyAlgorithmTag.Ed25519, SubkeyAlgorithm = PublicKeyAlgorithmTag.X25519,
                ExtraSubkeyAlgorithm = PublicKeyAlgorithmTag.MLKem768_X25519, Hash = HashAlgorithmTag.Sha512,
            },
            new KeyProfile
            {
                Name = "rfc9580-gcm", Version = 6, Aead = AeadAlgorithmTag.Gcm,
                Description = "v6 key, Ed25519 primary key and X25519 subkey, preferring AES-256/GCM (for tests)",
                PrimaryAlgorithm = PublicKeyAlgorithmTag.Ed25519, SubkeyAlgorithm = PublicKeyAlgorithmTag.X25519,
                Hash = HashAlgorithmTag.Sha512,
            },
            new KeyProfile
            {
                Name = "rfc9580-sign-only", Version = 6, SigningOnly = true,
                Description = "v6 key, Ed25519 primary key without an encryption subkey (for tests)",
                PrimaryAlgorithm = PublicKeyAlgorithmTag.Ed25519, Hash = HashAlgorithmTag.Sha512,
            },
            new KeyProfile
            {
                Name = "rfc9980", Alias = "security", Version = 6,
                Description = "v6 key, ML-DSA-65+Ed25519 primary key and ML-KEM-768+X25519 subkey",
                PrimaryAlgorithm = PublicKeyAlgorithmTag.MLDsa65_Ed25519,
                SubkeyAlgorithm = PublicKeyAlgorithmTag.MLKem768_X25519, Hash = HashAlgorithmTag.Sha3_256,
            },
            new KeyProfile
            {
                Name = "rfc9980-high", Version = 6,
                Description = "v6 key, ML-DSA-87+Ed448 primary key and ML-KEM-1024+X448 subkey",
                PrimaryAlgorithm = PublicKeyAlgorithmTag.MLDsa87_Ed448,
                SubkeyAlgorithm = PublicKeyAlgorithmTag.MLKem1024_X448, Hash = HashAlgorithmTag.Sha3_512,
            },
            new KeyProfile
            {
                Name = "rfc9980-slh-128s", Version = 6,
                Description = "v6 key, SLH-DSA-SHAKE-128s primary key and ML-KEM-768+X25519 subkey",
                PrimaryAlgorithm = PublicKeyAlgorithmTag.SlhDsa_Shake128s,
                SubkeyAlgorithm = PublicKeyAlgorithmTag.MLKem768_X25519, Hash = HashAlgorithmTag.Sha3_256,
            },
            new KeyProfile
            {
                Name = "rfc9980-slh-128f", Version = 6,
                Description = "v6 key, SLH-DSA-SHAKE-128f primary key and ML-KEM-768+X25519 subkey",
                PrimaryAlgorithm = PublicKeyAlgorithmTag.SlhDsa_Shake128f,
                SubkeyAlgorithm = PublicKeyAlgorithmTag.MLKem768_X25519, Hash = HashAlgorithmTag.Sha3_256,
            },
            new KeyProfile
            {
                Name = "rfc9980-slh-256s", Version = 6,
                Description = "v6 key, SLH-DSA-SHAKE-256s primary key and ML-KEM-1024+X448 subkey",
                PrimaryAlgorithm = PublicKeyAlgorithmTag.SlhDsa_Shake256s,
                SubkeyAlgorithm = PublicKeyAlgorithmTag.MLKem1024_X448, Hash = HashAlgorithmTag.Sha512,
            },
        };

        private static KeyProfile FindKeyProfile(string requested)
        {
            if (requested == null)
                return KeyProfiles[0];

            KeyProfile profile = KeyProfiles.FirstOrDefault(p => p.Name == requested || p.Alias == requested);
            return profile ?? throw new SopException(ExitCode.UnsupportedProfile, "unsupported profile: " + requested);
        }

        private static int GenerateKey(Arguments args)
        {
            bool armor = !args.Flag("--no-armor");
            KeyProfile profile = FindKeyProfile(args.Option("--profile"));
            string passwordFile = args.Option("--with-key-password");
            List<string> userIds = args.RemainingPositionals();
            args.Finish();

            if (userIds.Count > 1)
                throw new SopException(ExitCode.UnsupportedOption, "only one user ID is supported");

            char[] password = passwordFile == null ? null : ReadPassword(passwordFile);
            string userId = userIds.Count > 0 ? userIds[0] : "";
            PgpSecretKeyRing ring = profile.Version == 4
                ? GenerateVersion4Ring(profile, userId, password)
                : GenerateVersion6Ring(profile, userId, password);

            WriteOutput(armor, ring.Encode);
            return ExitCode.Ok;
        }

        private static PgpKeyPair NewKeyPair(PublicKeyAlgorithmTag algorithm, int version)
        {
            DateTime now = DateTime.UtcNow;
            switch (algorithm)
            {
            case PublicKeyAlgorithmTag.EdDsa_Legacy:
            {
                var generator = new Ed25519KeyPairGenerator();
                generator.Init(new Ed25519KeyGenerationParameters(Random));
                return new PgpKeyPair(version, algorithm, generator.GenerateKeyPair(), now);
            }
            case PublicKeyAlgorithmTag.Ed25519:
            {
                var generator = new Ed25519KeyPairGenerator();
                generator.Init(new Ed25519KeyGenerationParameters(Random));
                return new PgpKeyPair(version, algorithm, generator.GenerateKeyPair(), now);
            }
            case PublicKeyAlgorithmTag.ECDH:
            case PublicKeyAlgorithmTag.X25519:
            {
                var generator = new X25519KeyPairGenerator();
                generator.Init(new X25519KeyGenerationParameters(Random));
                return new PgpKeyPair(version, algorithm, generator.GenerateKeyPair(), now);
            }
            case PublicKeyAlgorithmTag.MLDsa65_Ed25519:
            {
                var privateKey = new MLDsa65Ed25519PrivateKeyParameters(Random);
                return new PgpKeyPair(version, algorithm, privateKey.GeneratePublicKey(), privateKey, now);
            }
            case PublicKeyAlgorithmTag.MLDsa87_Ed448:
            {
                var privateKey = new MLDsa87Ed448PrivateKeyParameters(Random);
                return new PgpKeyPair(version, algorithm, privateKey.GeneratePublicKey(), privateKey, now);
            }
            case PublicKeyAlgorithmTag.SlhDsa_Shake128s:
            case PublicKeyAlgorithmTag.SlhDsa_Shake128f:
            case PublicKeyAlgorithmTag.SlhDsa_Shake256s:
            {
                var parameters = algorithm == PublicKeyAlgorithmTag.SlhDsa_Shake128s
                    ? SlhDsaParameters.slh_dsa_shake_128s
                    : algorithm == PublicKeyAlgorithmTag.SlhDsa_Shake128f
                        ? SlhDsaParameters.slh_dsa_shake_128f
                        : SlhDsaParameters.slh_dsa_shake_256s;
                var generator = new SlhDsaKeyPairGenerator();
                generator.Init(new SlhDsaKeyGenerationParameters(Random, parameters));
                AsymmetricCipherKeyPair pair = generator.GenerateKeyPair();
                return new PgpKeyPair(version, algorithm, pair.Public, pair.Private, now);
            }
            case PublicKeyAlgorithmTag.MLKem768_X25519:
            {
                var privateKey = new MLKem768X25519PrivateKeyParameters(Random);
                return new PgpKeyPair(version, algorithm, privateKey.GeneratePublicKey(), privateKey, now);
            }
            case PublicKeyAlgorithmTag.MLKem1024_X448:
            {
                var privateKey = new MLKem1024X448PrivateKeyParameters(Random);
                return new PgpKeyPair(version, algorithm, privateKey.GeneratePublicKey(), privateKey, now);
            }
            default:
                throw new ArgumentException("no key generation for " + algorithm);
            }
        }

        /// <summary>
        /// A version 6 key as RFC 9580 10.1 and RFC 9980 7.1 describe it: a direct-key signature with the key flags and
        /// the preferences of the key (AES-256 and OCB first), a user ID certification if there is a user ID, and an
        /// encryption subkey.
        /// </summary>
        private static PgpSecretKeyRing GenerateVersion6Ring(KeyProfile profile, string userId, char[] password)
        {
            PgpKeyPair primary = NewKeyPair(profile.PrimaryAlgorithm, 6);

            var directKey = new PgpSignatureSubpacketGenerator();
            directKey.SetKeyFlags(false, PgpKeyFlags.CanCertify | PgpKeyFlags.CanSign);
            directKey.SetFeature(false, (byte)(Features.FEATURE_MODIFICATION_DETECTION | Features.FEATURE_SEIPD_V2));
            directKey.SetPreferredSymmetricAlgorithms(false,
                new[]{ (int)SymmetricKeyAlgorithmTag.Aes256, (int)SymmetricKeyAlgorithmTag.Aes128 });
            var ciphersuites = new List<PreferredAeadCiphersuites.Combination>();
            if (profile.Aead != AeadAlgorithmTag.Ocb)
            {
                ciphersuites.Add(new PreferredAeadCiphersuites.Combination(SymmetricKeyAlgorithmTag.Aes256,
                    profile.Aead));
            }
            ciphersuites.Add(new PreferredAeadCiphersuites.Combination(SymmetricKeyAlgorithmTag.Aes256,
                AeadAlgorithmTag.Ocb));
            ciphersuites.Add(new PreferredAeadCiphersuites.Combination(SymmetricKeyAlgorithmTag.Aes128,
                AeadAlgorithmTag.Ocb));
            directKey.SetPreferredAeadCiphersuites(false, ciphersuites.ToArray());
            directKey.SetPreferredHashAlgorithms(false, new[]
            {
                (int)HashAlgorithmTag.Sha3_512, (int)HashAlgorithmTag.Sha3_256, (int)HashAlgorithmTag.Sha512,
                (int)HashAlgorithmTag.Sha256,
            });

            PgpSecretKeyProtection protection = password == null
                ? PgpSecretKeyProtection.None
                : PgpSecretKeyProtection.AeadArgon2(SymmetricKeyAlgorithmTag.Aes256, AeadAlgorithmTag.Ocb,
                    S2k.Argon2Params.MemoryConstrainedParameters(Random), Encoding.UTF8.GetBytes(password));

            var generator = new PgpKeyRingGenerator(primary, profile.Hash, directKey.Generate(), null, protection,
                Random);
            if (userId.Length > 0)
            {
                generator.AddUserId(userId, PgpSignature.PositiveCertification, null, null);
            }

            var subkeyPackets = new PgpSignatureSubpacketGenerator();
            subkeyPackets.SetKeyFlags(false, PgpKeyFlags.CanEncryptCommunications | PgpKeyFlags.CanEncryptStorage);
            if (!profile.SigningOnly)
            {
                generator.AddSubKey(NewKeyPair(profile.SubkeyAlgorithm, 6), subkeyPackets.Generate(), null);
            }
            if (profile.ExtraSubkeyAlgorithm.HasValue)
            {
                generator.AddSubKey(NewKeyPair(profile.ExtraSubkeyAlgorithm.Value, 6), subkeyPackets.Generate(), null);
            }

            return generator.GenerateSecretKeyRing();
        }

        /// <summary>
        /// v4 key: Ed25519 (legacy) primary key for certification and signing and an encryption subkey (ML-KEM-768+X25519
        /// or Curve25519 ECDH), advertising only v1 SEIPD so that peers use a v3 PKESK.
        /// </summary>
        private static PgpSecretKeyRing GenerateVersion4Ring(KeyProfile profile, string userId, char[] password)
        {
            PgpKeyPair primary = NewKeyPair(profile.PrimaryAlgorithm, 4);

            var hashed = new PgpSignatureSubpacketGenerator();
            hashed.SetKeyFlags(false, PgpKeyFlags.CanCertify | PgpKeyFlags.CanSign);
            hashed.SetFeature(false, Features.FEATURE_MODIFICATION_DETECTION);
            hashed.SetPreferredSymmetricAlgorithms(false,
                new int[]{ (int)SymmetricKeyAlgorithmTag.Aes256, (int)SymmetricKeyAlgorithmTag.Aes128 });
            hashed.SetPreferredHashAlgorithms(false,
                new int[]{ (int)HashAlgorithmTag.Sha512, (int)HashAlgorithmTag.Sha256 });
            hashed.SetIssuerFingerprint(false, primary.PublicKey);

            var encAlgorithm = password == null ? SymmetricKeyAlgorithmTag.Null : SymmetricKeyAlgorithmTag.Aes256;
            var krg = new PgpKeyRingGenerator(PgpSignature.PositiveCertification, primary, userId, encAlgorithm,
                profile.Hash, password ?? new char[0], true, hashed.Generate(), null, Random);

            PgpKeyPair subKeyPair = NewKeyPair(profile.SubkeyAlgorithm, 4);
            var subHashed = new PgpSignatureSubpacketGenerator();
            subHashed.SetKeyFlags(false, PgpKeyFlags.CanEncryptCommunications | PgpKeyFlags.CanEncryptStorage);
            subHashed.SetIssuerFingerprint(false, primary.PublicKey);
            krg.AddSubKey(subKeyPair, subHashed.Generate(), null, HashAlgorithmTag.Sha256);

            return krg.GenerateSecretKeyRing();
        }
    }
}
