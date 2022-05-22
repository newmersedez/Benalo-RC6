using System;
using System.Text;

namespace RC6
{
    internal static class Program
    {
        public static void Main()
        {
            /* 128 */
            var key1 = new byte[] {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
            byte[] initializationVector1 = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
            var crypto = new CipherContext(EncryptionMode.ECB, initializationVector1, "kekw");
            crypto.Encrypter = new RC6(key1, 128);

            const string text = "lalkalklaklaklaklakalkalkalaklaklakalkalklk1414241241241242141242142142";
            var byteText =  Encoding.ASCII.GetBytes(text);
            var encrypted = crypto.Encrypt(byteText);
            var decrypted = crypto.Decrypt(encrypted);
            
            Console.WriteLine("Default = {0}", text);
            Console.WriteLine("Decrypt = {0}", Encoding.UTF8.GetString(decrypted));
        }
    }
}