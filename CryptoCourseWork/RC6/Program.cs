using System;
using System.Text;

namespace RC6
{
    public static class Program
    {
        private static void Main()
        {
            var key = new byte[] {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
            byte[] initializationVector = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
            var crypto = new CipherContext(EncryptionMode.OFB, initializationVector, "");
            crypto.Encrypter = new RC6(key, 128);

            const string text = "12345";
            var byteText =  Encoding.ASCII.GetBytes(text);
            var encrypted = crypto.Encrypt(byteText);
            var decrypted = crypto.Decrypt(encrypted);
            
            Console.WriteLine("Default = {0}", text);
            Console.WriteLine("Encrypted = {0}", Encoding.UTF8.GetString(encrypted));
            Console.WriteLine("Decrypted = {0}", Encoding.UTF8.GetString(decrypted));

        }
    }
}