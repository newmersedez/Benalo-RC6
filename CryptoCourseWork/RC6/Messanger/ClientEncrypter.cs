namespace RC6.Messanger
{
    public sealed class ClientEncrypter
    {
        private readonly IBaseDecorator _algorithm;

        public ClientEncrypter(IBaseDecorator algorithm)
        {
            _algorithm = algorithm;
        }

        public byte[] Encrypt(string message)
        {
            return _algorithm.Encrypt(message);
        }

        public string Decrypt(byte[] message)
        {
            return _algorithm.Decrypt(message);
        }
    }
}