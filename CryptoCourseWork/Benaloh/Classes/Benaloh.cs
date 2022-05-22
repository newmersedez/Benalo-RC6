using System;
using System.Numerics;
using Benaloh.RSA.Classes;

namespace Benaloh
{
    public enum PrimalityTestMode
    {
        Fermat,
        SolovayStrassen,
        MillerRabin
    }
    
    public sealed class Benaloh
    {
        private struct Keys
        {
            public BigInteger n;
            public BigInteger y, r;
            public BigInteger f, x;
        }

        private sealed class BenalohKeysGenerator
        {
            
        }
    }
}