using System;

namespace RC6
{
    public sealed class RC6: ICrypto
    {
        private readonly uint[] _roundKeys;
        
        private sealed class KeysGenerator : IKeysGenerator
        {
            public uint[] GenerateRoundKeys(byte[] key, uint length)
            {
                var c = length switch
                {
                    128 => 4,
                    192 => 6,
                    256 => 8,
                    _ => throw new ArgumentException(null, nameof(length))
                };

                int i, j;
                var L = new uint[c];
                for (i = 0; i < c; i++)
                {
                    L[i] = BitConverter.ToUInt32(key, i * 4);
                }

                var roundKey = new uint[2 * RC6Utils.R + 4];
                roundKey[0] = RC6Utils.P32;
                for (i = 1; i < 2 * RC6Utils.R + 4; i++)
                    roundKey[i] = roundKey[i - 1] + RC6Utils.Q32;

                i = j = 0;
                uint A = 0, B = 0;
                var V = 3 * Math.Max(c, 2 * RC6Utils.R + 4);
                for (var s = 1; s <= V; ++s)
                {
                    A = roundKey[i] = RC6Utils.LeftShift(roundKey[i] + A + B, 3);
                    B = L[j] = RC6Utils.LeftShift(L[j] + A + B, (int)(A + B));
                    i = (i + 1) % (2 * RC6Utils.R + 4);
                    j = (j + 1) % c;
                }

                return roundKey;
            }
        }
        
        public RC6(byte[] key, uint length)
        {
            if (length != 128 && length != 192 && length != 256)
                throw new ArgumentException(null, nameof(length));

            var keygen = new KeysGenerator();
            _roundKeys = keygen.GenerateRoundKeys(key, length);
        }

        private static byte[] ToArrayBytes(uint[] uints, int length)
        {
            var arrayBytes = new byte[length * 4];
            for (var i = 0; i < length; ++i)
            {
                var temp = BitConverter.GetBytes(uints[i]);
                temp.CopyTo(arrayBytes, i * 4);
            }
            return arrayBytes;
        }
        
        public byte[] Encrypt(byte[] block)
        {
            var i = block.Length;
            while (i % 16 != 0)
                i++;
            
            var text = new byte[i];
            block.CopyTo(text, 0);
            var cipherText = new byte[i];
            for (i = 0; i < text.Length; i += 16)
            {
                var A = BitConverter.ToUInt32(text, i);
                var B = BitConverter.ToUInt32(text, i + 4);
                var C = BitConverter.ToUInt32(text, i + 8);
                var D = BitConverter.ToUInt32(text, i + 12);

                B += _roundKeys[0];
                D += _roundKeys[1];
                for (var j = 1; j <= RC6Utils.R; ++j)
                {
                    var t = RC6Utils.LeftShift((B * (2 * B + 1)), (int)(Math.Log(RC6Utils.W, 2)));
                    var u = RC6Utils.LeftShift((D * (2 * D + 1)), (int)(Math.Log(RC6Utils.W, 2)));
                    A = (RC6Utils.LeftShift((A ^ t), (int)u)) + _roundKeys[j * 2];
                    C = (RC6Utils.LeftShift((C ^ u), (int)t)) + _roundKeys[j * 2 + 1];
                    var  temp = A;
                    A = B;
                    B = C;
                    C = D;
                    D = temp;
                }
                A += _roundKeys[2 * RC6Utils.R + 2];
                C += _roundKeys[2 * RC6Utils.R + 3];
                var returnBlock = ToArrayBytes(new [] {A, B, C, D}, 4);
                returnBlock.CopyTo(cipherText, i);
            }
            return cipherText;
        }

        public byte[] Decrypt(byte[] block)
        {
            var plainText = new byte[block.Length];
            for (var i = 0; i < block.Length; i += 16)
            {
                var A = BitConverter.ToUInt32(block, i);
                var B = BitConverter.ToUInt32(block, i + 4);
                var C = BitConverter.ToUInt32(block, i + 8);
                var D = BitConverter.ToUInt32(block, i + 12);

                C -= _roundKeys[2 * RC6Utils.R + 3];
                A -= _roundKeys[2 * RC6Utils.R + 2];
                for (var j = RC6Utils.R; j >= 1; --j)
                {
                    var temp = D;
                    D = C;
                    C = B;
                    B = A;
                    A = temp;
                    var u = RC6Utils.LeftShift((D * (2 * D + 1)), (int)Math.Log(RC6Utils.W, 2));
                    var t = RC6Utils.LeftShift((B * (2 * B + 1)), (int)Math.Log(RC6Utils.W, 2));
                    C = RC6Utils.RightShift((C - _roundKeys[2 * j + 1]), (int)t) ^ u;
                    A = RC6Utils.RightShift((A - _roundKeys[2 * j]), (int)u) ^ t;
                }
                D -= _roundKeys[1];
                B -= _roundKeys[0];
                var returnBlock = ToArrayBytes(new [] {A, B, C, D}, 4);
                returnBlock.CopyTo(plainText, i);
            }
            return plainText;
        }
    }
}