using System.Numerics;

namespace Benaloh
{
    public interface ICrypto
    {        
        public BigInteger Encrypt(BigInteger message);
        public BigInteger Decrypt(BigInteger message);
    }
}