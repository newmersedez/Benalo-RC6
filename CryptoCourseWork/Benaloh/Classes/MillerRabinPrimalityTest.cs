using System;
using System.Numerics;
using Microsoft.VisualBasic.CompilerServices;

namespace Benaloh
{
    public sealed class MillerRabinPrimalityTest : IPrimalityTest
    {
        public bool SimplicityTest(BigInteger n, double minProbability)
        {
            if (minProbability is not (>= 0.5 and < 1))
                throw new ArgumentOutOfRangeException(nameof(minProbability), "minProbability must be [0.5, 1)");
            if (n == 1)
                return false;

            var d = n - 1;
            var degree = 0;
            while (d % 2 == 0)
            {
                d /= 2;
                degree += 1;
            }

            for (var i = 0; 1.0 - Math.Pow(4, -i) <= minProbability; ++i)
            {
                var a = BenalohUtils.GenerateRandomInteger(2, n - 1);
                var x = BigInteger.ModPow(a, d, n);
                if (x == 1 || x == n - 1)
                    continue;

                for (var r = 1; r < degree; ++r)
                {
                    x = BigInteger.ModPow(x, 2, n);
                    if (x == 1)
                        return false;
                    if (x == n - 1)
                        break;
                }

                if (x != n - 1)
                    return false;
            }

            return true;
        }
    }
}