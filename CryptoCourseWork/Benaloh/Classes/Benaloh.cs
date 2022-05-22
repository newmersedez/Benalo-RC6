using System;
using System.Numerics;
using Benaloh.RSA.Classes;

namespace Benaloh
{
    public sealed class Benaloh : ICrypto
    {
        private sealed class KeysGenerator : IKeysGenerator
        {
            public Keys GenerateKeys(BigInteger message)
            {
                throw new NotImplementedException();
            }
        }

        public BigInteger Encrypt(BigInteger message)
        {
            throw new NotImplementedException();
        }

        public BigInteger Decrypt(BigInteger message)
        {
            throw new NotImplementedException();
        }
    }
}