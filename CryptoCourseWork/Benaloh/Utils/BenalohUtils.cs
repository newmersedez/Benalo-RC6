using System;
using System.Numerics;
using System.Security.Cryptography;

namespace Benaloh
{
    internal static class BenalohUtils
    {
        public static BigInteger Legendre(BigInteger a, BigInteger p)
        {
            if (p < 2)
                throw new ArgumentOutOfRangeException(nameof(p), "P must not be < 2");
            
            if (a == 0 || a == 1)
                return a;
            
            BigInteger result;
            if (a % 2 == 0)
            {
                result = Legendre(a / 2, p);
                if (((p * p - 1) & 8) != 0)
                    result = -result;
            }
            else
            {
                result = Legendre(p % a, a);
                if (((a - 1) * (p - 1) & 4) != 0)
                    result = -result;
            }
            
            return result;
        }

        public static BigInteger Jacobi(BigInteger a, BigInteger b)
        {
            if (BigInteger.GreatestCommonDivisor(a, b) != 1)
                return 0;
            
            var r = 1;
            if (a < 0)
            {
                a = -a;
                if (b % 4 == 3)
                    r = -r;
            }
            do
            {
                var t = 0;
                while (a % 2 == 0)
                {
                    a /= 2;
                    ++t;
                }
                if (t % 2 == 1)
                {
                    if (b % 8 == 3 || b % 8 == 5)
                        r = -r;
                }

                if (a % 4 == b % 4 && a % 4 == 3)
                    r = -r;

                var c = a;
                a = b % c;
                b = c;
            } while (a != 0);
            
            return r;
        }
        
        public static BigInteger GenerateRandomInteger(BigInteger left, BigInteger right)
        {
            var rndGenerator = RandomNumberGenerator.Create();
            var bytes = right.ToByteArray();
            BigInteger r;
            do
            {
                rndGenerator.GetBytes(bytes);
                r = new BigInteger(bytes);
            } while (!(r >= left && r <= right));

            return r;
        }
    }
}