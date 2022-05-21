namespace RC6
{
    internal interface IKeyGen
    {
        public uint[] GenerateRoundKeys(byte[] key, uint length);
    }
}