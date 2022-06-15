namespace RC6.Messanger
{
    public interface IBaseDecorator
    {
        public byte[] Encrypt(string message);
        public string Decrypt(byte[] byteMessage);
    }
}