using System.Numerics;

namespace Benaloh
{
    internal interface ICrypto
    {        
        public BigInteger Encrypt(BigInteger message);
        
        public BigInteger Decrypt(BigInteger message);

        public void GenerateKeys(BigInteger message);
    }
}