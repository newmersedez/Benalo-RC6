using System;
using System.Numerics;
using System.Text;
using Benaloh;
using RC6.Messanger;

namespace RC6
{
    internal static class Program
    {
        public static void Main()
        {
            // const uint length = 128;
            // var initVector = Messanger.RC6Utils.GenerateInitializationVector(length);
            // var key = Messanger.RC6Utils.GenerateKey(length);
            // IBaseDecorator algorithm = new RC6Decorator(EncryptionMode.ECB, initVector, "", key, length);
            //
            // while (true)
            // {
            //     Console.WriteLine("Enter message: ");
            //     var message = Console.ReadLine();
            //     var encryptedMessage = algorithm.Encrypt(message);
            //     var decryptedMessage = algorithm.Decrypt(encryptedMessage);
            //     Console.WriteLine($"Default = {message}");
            //     Console.WriteLine($"Encrypted = {encryptedMessage}");
            //     Console.WriteLine($"Decrypted = {decryptedMessage}");
            // }
            
            var key = new byte[] { 1, 1, 1, 1};
            var mode = PrimalityTestMode.Fermat;
            var message = new BigInteger(key);
            var minProbability = 0.5;
            var length = (ulong)message.GetByteCount() + 1;
            var keyAlgorithm = new Benaloh.Benaloh(message, mode, minProbability, length);

            
            var encrypted = keyAlgorithm.Encrypt(new BigInteger(key));
            var decrypted = keyAlgorithm.Decrypt(encrypted);
            
            Console.WriteLine($"Before = {new BigInteger(key)}");
            Console.WriteLine($"After = {decrypted}");
        }
    }
}