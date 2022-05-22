using System;
using System.Numerics;

namespace Benaloh
{
    public static class Program
    {
        private static void Main(string[] args)
        {
            var message = new BigInteger(1000);
            var crypto = new Benaloh(message, PrimalityTestMode.Fermat, 0.7, (ulong) message.GetByteCount() + 1);

            var lalka = new BigInteger(228);
            var encrypted = crypto.Encrypt(lalka);
            var decrypted = crypto.Decrypt(encrypted);
            
            Console.WriteLine("Default = {0}", lalka);
            Console.WriteLine("Encrypted = {0}", encrypted);
            Console.WriteLine("Decrypted = {0}", decrypted);
        }
    }
}