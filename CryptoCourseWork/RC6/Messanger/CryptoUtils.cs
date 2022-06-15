using System;
using System.Numerics;

namespace RC6.Messanger
{
    public static class RC6Utils
    {
        public enum AlgoType
        {
            RC6,
            Benaloh
        }

        public static byte[] GenerateInitializationVector(uint length)
        {
            if (length != 128 && length != 192 && length != 256)
                throw new ArgumentException("Incorrect init vector length", nameof(length));
            
            var random = new Random();
            var initializationVector = new byte[length / 8];
            random.NextBytes(initializationVector);
            return initializationVector;
        }

        public static byte[] GenerateKey(uint length)
        {
            if (length != 128 && length != 192 && length != 256)
                throw new ArgumentException("Incorrect init vector length", nameof(length));
            
            var random = new Random();
            var key = new byte[length / 8];
            random.NextBytes(key);
            return key;
        }
    }

    public static class BenalohUtils
    {
        public static BigInteger GenerateKey(BigInteger message)
        {
            throw new NotImplementedException();
        }
    }
}