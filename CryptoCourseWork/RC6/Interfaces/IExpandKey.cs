namespace RC6
{
    public interface IExpandKey
    {
        public uint[] GenerateRoundKeys(byte[] key, uint length);
    }
}