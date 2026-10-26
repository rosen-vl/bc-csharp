using System;

using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Tools.PgpInterop
{
    internal static partial class Program
    {
        /// <summary>
        /// Non-SOP extension: print the outer packet structure (PKESK/SKESK/SEIPD versions, algorithms, chunk size
        /// octets, key algorithms, signature salts, features), used by the interop scripts to check what a peer
        /// produced.
        /// </summary>
        private static int DumpPackets(Arguments args)
        {
            args.Finish();
            byte[] data = ReadStdin();
            if (IsArmored(data))
            {
                data = Streams.ReadAll(new ArmoredInputStream(new System.IO.MemoryStream(data, false)));
            }

            try
            {
                return PrintPackets(data);
            }
            catch (IndexOutOfRangeException)
            {
                throw new SopException(ExitCode.BadData, "truncated packet");
            }
        }

        private static int PrintPackets(byte[] data)
        {
            int pos = 0;
            while (pos < data.Length)
            {
                int header = data[pos++], tag, length;
                bool partial = false;
                if ((header & 0x40) != 0)
                {
                    tag = header & 0x3F;
                    int first = data[pos++];
                    if (first < 192)
                    {
                        length = first;
                    }
                    else if (first < 224)
                    {
                        length = ((first - 192) << 8) + data[pos++] + 192;
                    }
                    else if (first == 255)
                    {
                        length = (data[pos] << 24) | (data[pos + 1] << 16) | (data[pos + 2] << 8) | data[pos + 3];
                        pos += 4;
                    }
                    else
                    {
                        length = 1 << (first & 0x1F);
                        partial = true;
                    }
                }
                else
                {
                    tag = (header >> 2) & 0x0F;
                    switch (header & 3)
                    {
                    case 0:
                        length = data[pos++];
                        break;
                    case 1:
                        length = (data[pos] << 8) | data[pos + 1];
                        pos += 2;
                        break;
                    case 2:
                        length = (data[pos] << 24) | (data[pos + 1] << 16) | (data[pos + 2] << 8) | data[pos + 3];
                        pos += 4;
                        break;
                    default:
                        length = data.Length - pos;
                        partial = true;
                        break;
                    }
                }

                int body = pos;
                int available = System.Math.Min(length, data.Length - body);
                Console.WriteLine(DescribePacket((PacketTag)tag, data, body, available));
                if (partial || tag == (int)PacketTag.SymmetricEncryptedIntegrityProtected)
                    break;

                pos = body + length;
            }
            return ExitCode.Ok;
        }

        private static string DescribePacket(PacketTag tag, byte[] data, int body, int length)
        {
            int version = data[body];
            switch (tag)
            {
            case PacketTag.PublicKeyEncryptedSession:
                return DescribePkesk(data, body);
            case PacketTag.SymmetricKeyEncryptedSessionKey:
                return version == 6
                    ? $"SKESK v6 cipher={(SymmetricKeyAlgorithmTag)data[body + 2]} " +
                        $"aead={(AeadAlgorithmTag)data[body + 3]} s2k={data[body + 5]}"
                    : $"SKESK v{version}";
            case PacketTag.SymmetricEncryptedIntegrityProtected:
                return version == 2
                    ? $"SEIPD v2 cipher={(SymmetricKeyAlgorithmTag)data[body + 1]} " +
                        $"aead={(AeadAlgorithmTag)data[body + 2]} chunk={data[body + 3]}"
                    : $"SEIPD v{version}";
            case PacketTag.OnePassSignature:
                return version == 6
                    ? $"OPS v6 type=0x{data[body + 1]:x2} hash={(HashAlgorithmTag)data[body + 2]} " +
                        $"alg={(PublicKeyAlgorithmTag)data[body + 3]} salt={data[body + 4]}"
                    : $"OPS v{version}";
            case PacketTag.PublicKey:
            case PacketTag.PublicSubkey:
            case PacketTag.SecretKey:
            case PacketTag.SecretSubkey:
                return $"{tag} v{version} alg={(PublicKeyAlgorithmTag)data[body + 5]}";
            case PacketTag.Signature:
                return DescribeSignature(data, body);
            default:
                return $"{tag} ({length} octets)";
            }
        }

        private static string DescribePkesk(byte[] data, int body)
        {
            int version = data[body];
            if (version == 3)
            {
                return $"PKESK v3 keyid={Hex.ToHexString(data, body + 1, 8)} alg={(PublicKeyAlgorithmTag)data[body + 9]}";
            }
            if (version != 6)
                return $"PKESK v{version}";

            int keyLength = data[body + 1];
            if (keyLength == 0)
                return $"PKESK v6 anonymous alg={(PublicKeyAlgorithmTag)data[body + 2]}";

            return $"PKESK v6 key=v{data[body + 2]} fingerprint={Hex.ToHexString(data, body + 3, keyLength - 1)} " +
                $"alg={(PublicKeyAlgorithmTag)data[body + 2 + keyLength]}";
        }

        private static string DescribeSignature(byte[] data, int body)
        {
            int version = data[body];
            if (version != 4 && version != 6)
                return $"Signature v{version}";

            int lengthOctets = version == 6 ? 4 : 2;
            int hashedStart = body + 4 + lengthOctets;
            int hashedLength = version == 6
                ? (data[body + 4] << 24) | (data[body + 5] << 16) | (data[body + 6] << 8) | data[body + 7]
                : (data[body + 4] << 8) | data[body + 5];

            string features = "";
            for (int i = hashedStart, end = hashedStart + hashedLength; i < end;)
            {
                int subLength = data[i++];
                if (subLength >= 192 && subLength < 255)
                {
                    subLength = ((subLength - 192) << 8) + data[i++] + 192;
                }
                else if (subLength == 255)
                {
                    subLength = (data[i] << 24) | (data[i + 1] << 16) | (data[i + 2] << 8) | data[i + 3];
                    i += 4;
                }
                if ((data[i] & 0x7F) == (int)SignatureSubpacketTag.Features)
                {
                    features = $" features=0x{data[i + 1]:x2}";
                }
                i += subLength;
            }

            string description = $"Signature v{version} type=0x{data[body + 1]:x2} " +
                $"alg={(PublicKeyAlgorithmTag)data[body + 2]} hash={(HashAlgorithmTag)data[body + 3]}{features}";
            if (version != 6)
                return description;

            // hashed area, unhashed area, 2 octets of digest prefix, salt length
            int unhashedStart = hashedStart + hashedLength + 4;
            int unhashedLength = (data[unhashedStart - 4] << 24) | (data[unhashedStart - 3] << 16)
                | (data[unhashedStart - 2] << 8) | data[unhashedStart - 1];
            int saltPosition = unhashedStart + unhashedLength + 2;
            return description + $" salt={data[saltPosition]}";
        }
    }
}
