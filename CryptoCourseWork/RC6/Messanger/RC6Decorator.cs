using System.Net;
using System.Text;

namespace RC6.Messanger
{
    public sealed class RC6Decorator : IBaseDecorator
    {
        private readonly CipherContext _cipherContext;

        public RC6Decorator(EncryptionMode mode, byte[] vector, string param, byte[] key, uint length)
        {
            _cipherContext = new CipherContext(mode, vector, param)
            {
                Encrypter = new RC6(key, length)
            };
        }

        public byte[] Encrypt(string message)
        {
            var byteMessage = Encoding.Unicode.GetBytes(message);
            var encryptedMessage = _cipherContext.Encrypt(byteMessage);
            return encryptedMessage;
        }

        public string Decrypt(byte[] byteMessage)
        {
            var decryptedMessage = _cipherContext.Decrypt(byteMessage);
            return Encoding.Unicode.GetString(decryptedMessage);
        }
    }
}