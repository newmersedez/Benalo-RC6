using System;
using System.Collections.Generic;

namespace RC6
{
    public sealed class RC6: ICrypto
    {
        private readonly IExpandKey _keygen;
        private byte[] _key;
        private uint _length;
        private uint[] _roundKeys;

        public RC6(byte[] key, uint length)
        {
            if (length != 128 && length != 192 && length != 256)
                throw new ArgumentException(null, nameof(length));
            
            _keygen = new RC6KeysGenerator();
            _key = key;
            _roundKeys = _keygen.GenerateRoundKeys(_key, length);
        }

        private static byte[] ToArrayBytes(IReadOnlyList<uint> uints, int length)
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

        public void GetRoundKeys(byte[] key, uint length)
        {
            _key = key;
            _length = length;
            _roundKeys = _keygen.GenerateRoundKeys(_key, _length);
        }
    }
}