using System;
using System.Diagnostics.CodeAnalysis;
using System.Numerics;

namespace Benaloh
{
    public static class Program
    {
        [SuppressMessage("ReSharper.DPA", "DPA0001: Memory allocation issues")]
        private static void Main(string[] args)
        {
            var msg = new BigInteger(255);
            var crypto = new Benaloh(msg, PrimalityTestMode.Fermat, 0.5, (ulong) msg.GetByteCount() + 1);
            
            var lalka = new BigInteger();
            Console.WriteLine("Default = {0}", lalka);
            var encrypted = crypto.Encrypt(lalka);
            Console.WriteLine("Encrypted = {0}", encrypted);
            var decrypted = crypto.Decrypt(encrypted);
            Console.WriteLine("Decrypted = {0}", decrypted);
        }
    }
}