namespace RC6
{
    internal interface IKeysGenerator
    {
        public uint[] GenerateRoundKeys(byte[] key, uint length);
    }
}