using System;
using System.Text;

namespace RC6
{
    public static class Program
    {
        private static void Main()
        {
            var key = new byte[] {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
            byte[] initializationVector = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
            var crypto = new CipherContext(EncryptionMode.ECB, initializationVector, "kekw");
            crypto.Encrypter = new RC6(key, 192);

            const string text = "lalkalklaklaklaklakalkalkalaklaklakalkalklk1414241241241242141242142142";
            var byteText =  Encoding.ASCII.GetBytes(text);
            var encrypted = crypto.Encrypt(byteText);
            var decrypted = crypto.Decrypt(encrypted);
            
            Console.WriteLine("Default = {0}", text);
            Console.WriteLine("Encrypt = {0}", Encoding.UTF8.GetString(encrypted));
            Console.WriteLine("Decrypt = {0}", Encoding.UTF8.GetString(decrypted));

        }
    }
}