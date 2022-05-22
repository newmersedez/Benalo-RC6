using System;
using System.Text;

namespace RC6
{
    public static class Program
    {
        private static void Main()
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
            Console.WriteLine("Encrypt = {0}", Encoding.UTF8.GetString(encrypted));
            Console.WriteLine("Decrypt = {0}", Encoding.UTF8.GetString(decrypted));

            /* 192 */
            var key2 = new byte[] {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
            byte[] initializationVector2 = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
            crypto.Encrypter = new RC6(key2, 192);
            crypto.InitializationVector = initializationVector2;
            
            encrypted = crypto.Encrypt(byteText);
            decrypted = crypto.Decrypt(encrypted);
            
            Console.WriteLine("Default = {0}", text);
            Console.WriteLine("Encrypt = {0}", Encoding.UTF8.GetString(encrypted));
            Console.WriteLine("Decrypt = {0}", Encoding.UTF8.GetString(decrypted));

            /* 256 */
            var key3 = new byte[] {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
            byte[] initializationVector3 = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
            crypto.Encrypter = new RC6(key3, 256);
            crypto.InitializationVector = initializationVector3;
            
            encrypted = crypto.Encrypt(byteText);
            decrypted = crypto.Decrypt(encrypted);
            
            Console.WriteLine("Default = {0}", text);
            Console.WriteLine("Encrypt = {0}", Encoding.UTF8.GetString(encrypted));
            Console.WriteLine("Decrypt = {0}", Encoding.UTF8.GetString(decrypted));
            
        }
    }
}