using System;

namespace RC6
{
    internal sealed class RC6KeysGenerator : IExpandKey
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
}