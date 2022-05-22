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
        private Keys _keys;
        private BigInteger u, a;
        
        private struct Keys
        {
            public BigInteger n;        // n = p * q
            public BigInteger y, r;     // public key
            public BigInteger phi, x;   // private key
        }

        private sealed class BenalohKeysGenerator
        {
            
        }
    }
}