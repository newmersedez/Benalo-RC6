namespace RC6
{
    public interface ICrypto
    {        
        public byte[] Encrypt(byte[] block);
        public byte[] Decrypt(byte[] block);
    }
}