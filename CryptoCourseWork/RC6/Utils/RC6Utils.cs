using System;

namespace RC6
{
    internal static class RC6Utils
    {
        public const uint P32 = 0xB7E15163;
        public const uint Q32 = 0x9E3779B9;
        public const int R = 20;
        public const int W = 32;
        public const int BlockSize = 16;
        
        public static uint RightShift(uint value, int shift)
        {
            return (value >> shift) | (value << (W - shift));
        }
        
        public static uint LeftShift(uint value, int shift)
        {
            return (value << shift) | (value >> (W - shift));
        }
    }
}