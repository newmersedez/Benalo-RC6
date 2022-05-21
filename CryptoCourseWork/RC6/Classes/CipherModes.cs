using System;
using System.Collections.Generic;

namespace RC6
{
    public enum EncryptionMode
    {
        ECB,
        CBC,
        CFB,
        OFB,
        CTR,
        RD,
        RDH
    };

    public class CipherContext
    {
        private readonly byte[] _key;
        private readonly EncryptionMode _mode;
        private readonly byte[] _initializationVector;
        private int _cutSize;
        private string _strParam;
        internal ICrypto Encrypter { get; set; }

        public CipherContext(EncryptionMode mode, byte[] key, byte[] initializationVector = null, string strParam = null)
        {
            _key = key;
            _mode = mode;
            _initializationVector = initializationVector;
            _strParam = strParam;
        }

        private byte[] PaddingPkcs7(byte[] block)
        {
            byte mod = (byte) (RC6Utils.BlockSize - block.Length % RC6Utils.BlockSize);
            var paddedBlock = new byte[block.Length + mod];
            Array.Copy(block, paddedBlock, block.Length);
            Array.Fill(paddedBlock, mod, block.Length, mod);
            return paddedBlock;
        }

        private byte[] Encrypt(byte[] block)
        {
            var resultBlock = PaddingPkcs7(block);
            _cutSize = resultBlock[^1];
            var blocksList = new List<byte[]>();
            switch (_mode)
            {
                case EncryptionMode.ECB:
                {
                    var currBlock = new byte[RC6Utils.BlockSize];
                    for (var i = 0; i < resultBlock.Length / RC6Utils.BlockSize; ++i)
                    {
                        Array.Copy(resultBlock, i * RC6Utils.BlockSize, currBlock,
                            0, RC6Utils.BlockSize);
                        blocksList.Add(Encrypter.Encrypt(currBlock));
                    }

                    break;
                }

                case EncryptionMode.CBC:
                {
                    var prevBlock = new byte[RC6Utils.BlockSize];
                    var nextBlock = new byte[RC6Utils.BlockSize];
                    Array.Copy(_initializationVector, prevBlock, prevBlock.Length);
                    for (var i = 0; i < resultBlock.Length / RC6Utils.BlockSize; ++i)
                    {
                        Array.Copy(resultBlock, i * RC6Utils.BlockSize, nextBlock,
                            0, RC6Utils.BlockSize);
                        var xorResult = BitConverter.ToUInt64(nextBlock) ^ BitConverter.ToUInt64(prevBlock);
                        blocksList.Add(Encrypter.Encrypt(BitConverter.GetBytes(xorResult)));
                        Array.Copy(blocksList[i], prevBlock, RC6Utils.BlockSize);
                    }

                    break;
                }

                case EncryptionMode.CFB:
                {
                    var prevBlock = new byte[RC6Utils.BlockSize];
                    var nextBlock = new byte[RC6Utils.BlockSize];
                    Array.Copy(_initializationVector, prevBlock, prevBlock.Length);
                    for (var i = 0; i < resultBlock.Length / RC6Utils.BlockSize; ++i)
                    {
                        Array.Copy(resultBlock, i * RC6Utils.BlockSize, nextBlock,
                            0, RC6Utils.BlockSize);
                        var xorResult = BitConverter.ToUInt64(Encrypter.Encrypt(prevBlock))
                                        ^ BitConverter.ToUInt64(nextBlock);
                        blocksList.Add(BitConverter.GetBytes(xorResult));
                        Array.Copy(blocksList[i], prevBlock, RC6Utils.BlockSize);
                    }

                    break;
                }

                case EncryptionMode.OFB:
                {
                    var prevBlock = new byte[RC6Utils.BlockSize];
                    var nextBlock = new byte[RC6Utils.BlockSize];
                    Array.Copy(_initializationVector, prevBlock, prevBlock.Length);
                    for (var i = 0; i < resultBlock.Length / RC6Utils.BlockSize; ++i)
                    {
                        Array.Copy(resultBlock, i * RC6Utils.BlockSize, nextBlock,
                            0, RC6Utils.BlockSize);
                        var encryptedBlock = Encrypter.Encrypt(prevBlock);
                        var xorResult = BitConverter.ToUInt64(encryptedBlock) ^ BitConverter.ToUInt64(nextBlock);
                        blocksList.Add(BitConverter.GetBytes(xorResult));
                        Array.Copy(encryptedBlock, prevBlock, RC6Utils.BlockSize);
                    }

                    break;
                }

                case EncryptionMode.CTR:
                {
                    var IV = new byte[RC6Utils.BlockSize];
                    _initializationVector.CopyTo(IV, 0);
                    var counter = BitConverter.ToUInt64(IV);
                    var currBlock = new byte[RC6Utils.BlockSize];
                    for (int i = 0; i < resultBlock.Length / RC6Utils.BlockSize; ++i)
                    {
                        Array.Copy(resultBlock, i * RC6Utils.BlockSize, currBlock,
                            0, RC6Utils.BlockSize);
                        var xorResult = BitConverter.ToUInt64(Encrypter.Encrypt(IV)) ^
                                        BitConverter.ToUInt64(currBlock);
                        blocksList.Add(BitConverter.GetBytes(xorResult));
                        IV = BitConverter.GetBytes(++counter);
                    }

                    break;
                }

                case EncryptionMode.RD:
                {
                    var curBlock = new byte[RC6Utils.BlockSize];
                    var copyIV = new byte[8];
                    _initializationVector.CopyTo(copyIV, 0);
                    var IV = BitConverter.ToUInt64(copyIV);
                    var delta = BitConverter.ToUInt64(_initializationVector);
                    blocksList.Add(Encrypter.Encrypt(copyIV));
                    for (var i = 0; i < resultBlock.Length / RC6Utils.BlockSize; ++i)
                    {
                        Array.Copy(resultBlock, i * RC6Utils.BlockSize, curBlock, 0, RC6Utils.BlockSize);
                        var xorResult = BitConverter.ToUInt64(copyIV, 0) ^ BitConverter.ToUInt64(curBlock, 0);
                        blocksList.Add(Encrypter.Encrypt(BitConverter.GetBytes(xorResult)));
                        IV += delta;
                        copyIV = BitConverter.GetBytes(IV);
                    }

                    break;
                }

                case EncryptionMode.RDH:
                {
                    var curBlock = new byte[RC6Utils.BlockSize];
                    var copyIV = new byte[8];
                    Array.Copy(_initializationVector, 0, copyIV, 0, RC6Utils.BlockSize);
                    var IV = BitConverter.ToUInt64(copyIV);
                    var delta = BitConverter.ToUInt64(_initializationVector);
                    blocksList.Add(Encrypter.Encrypt(copyIV));
                    var xorResult = BitConverter.ToUInt64(copyIV, 0) ^
                                    BitConverter.ToUInt64(PaddingPkcs7(BitConverter.GetBytes(block.GetHashCode())));
                    blocksList.Add(BitConverter.GetBytes(xorResult));
                    for (var i = 0; i < resultBlock.Length / RC6Utils.BlockSize; ++i)
                    {
                        IV += delta;
                        copyIV = BitConverter.GetBytes(IV);
                        Array.Copy(resultBlock, i * RC6Utils.BlockSize, curBlock, 0, RC6Utils.BlockSize);
                        xorResult = BitConverter.ToUInt64(copyIV, 0) ^ BitConverter.ToUInt64(curBlock);
                        blocksList.Add(Encrypter.Encrypt(BitConverter.GetBytes(xorResult)));
                    }

                    break;
                }

                default:
                    throw new ArgumentOutOfRangeException(nameof(_mode), "Incorrect mode");
            }

            var connecterBlock = new byte[RC6Utils.BlockSize * blocksList.Count];
            for (var i = 0; i < blocksList.Count; ++i)
            {
                Array.Copy(blocksList[i], 0, connecterBlock, i * RC6Utils.BlockSize, RC6Utils.BlockSize);
            }

            return connecterBlock;
        }

        private byte[] Decrypt(byte[] block)
        {
            var blocksList = new List<byte[]>();
            switch (_mode)
            {
                case EncryptionMode.ECB:
                {
                    var currBlock = new byte[RC6Utils.BlockSize];
                    for (var i = 0; i < block.Length / RC6Utils.BlockSize; ++i)
                    {
                        Array.Copy(block, i * RC6Utils.BlockSize, currBlock,
                            0, RC6Utils.BlockSize);
                        blocksList.Add(Encrypter.Decrypt(currBlock));
                    }

                    break;
                }

                case EncryptionMode.CBC:
                {
                    var prevBlock = new byte[RC6Utils.BlockSize];
                    var curBlock = new byte[RC6Utils.BlockSize];
                    Array.Copy(_initializationVector, prevBlock, prevBlock.Length);
                    for (var i = 0; i < block.Length / RC6Utils.BlockSize; ++i)
                    {
                        Array.Copy(block, i * RC6Utils.BlockSize, curBlock,
                            0, RC6Utils.BlockSize);
                        var xorResult = BitConverter.ToUInt64(prevBlock) ^
                                        BitConverter.ToUInt64(Encrypter.Decrypt(curBlock));
                        blocksList.Add(BitConverter.GetBytes(xorResult));
                        Array.Copy(curBlock, prevBlock, RC6Utils.BlockSize);
                    }

                    break;
                }

                case EncryptionMode.CFB:
                {
                    var prevBlock = new byte[RC6Utils.BlockSize];
                    var nextBlock = new byte[RC6Utils.BlockSize];
                    Array.Copy(_initializationVector, prevBlock, prevBlock.Length);
                    for (var i = 0; i < block.Length / RC6Utils.BlockSize; ++i)
                    {
                        Array.Copy(block, i * RC6Utils.BlockSize, nextBlock,
                            0, RC6Utils.BlockSize);
                        var xorResult = BitConverter.ToUInt64(Encrypter.Encrypt(prevBlock)) ^
                                        BitConverter.ToUInt64(nextBlock);
                        blocksList.Add(BitConverter.GetBytes(xorResult));
                        Array.Copy(nextBlock, prevBlock, RC6Utils.BlockSize);
                    }

                    break;
                }

                case EncryptionMode.OFB:
                {
                    var prevBlock = new byte[RC6Utils.BlockSize];
                    var curBlock = new byte[RC6Utils.BlockSize];
                    Array.Copy(_initializationVector, prevBlock, prevBlock.Length);
                    for (var i = 0; i < block.Length / RC6Utils.BlockSize; ++i)
                    {
                        Array.Copy(block, i * RC6Utils.BlockSize, curBlock,
                            0, RC6Utils.BlockSize);
                        var encryptBlock = Encrypter.Encrypt(prevBlock);
                        var xorResult = BitConverter.ToUInt64(encryptBlock) ^ BitConverter.ToUInt64(curBlock);
                        blocksList.Add(BitConverter.GetBytes(xorResult));
                        Array.Copy(encryptBlock, prevBlock, RC6Utils.BlockSize);
                    }

                    break;
                }

                case EncryptionMode.CTR:
                {
                    var IV = new byte[RC6Utils.BlockSize];
                    _initializationVector.CopyTo(IV, 0);
                    var counter = BitConverter.ToUInt64(IV);
                    var currBlock = new byte[RC6Utils.BlockSize];
                    for (var i = 0; i < block.Length / RC6Utils.BlockSize; ++i)
                    {
                        Array.Copy(block, i * RC6Utils.BlockSize, currBlock,
                            0, RC6Utils.BlockSize);
                        var xorResult = BitConverter.ToUInt64(Encrypter.Encrypt(IV)) ^
                                        BitConverter.ToUInt64(currBlock);
                        blocksList.Add(BitConverter.GetBytes(xorResult));
                        IV = BitConverter.GetBytes(++counter);
                    }

                    break;
                }

                case EncryptionMode.RD:
                {
                    var curBlock = new byte[RC6Utils.BlockSize];
                    var copyIV = new byte[8];
                    var delta = BitConverter.ToUInt64(_initializationVector);
                    Array.Copy(block, 0, curBlock, 0, RC6Utils.BlockSize);
                    copyIV = Encrypter.Decrypt(curBlock);
                    var IV = BitConverter.ToUInt64(copyIV);
                    for (var i = 1; i < block.Length / RC6Utils.BlockSize; ++i)
                    {
                        Array.Copy(block, i * RC6Utils.BlockSize, curBlock, 0, RC6Utils.BlockSize);
                        var xorResult = BitConverter.ToUInt64(Encrypter.Decrypt(curBlock), 0) ^
                                        BitConverter.ToUInt64(copyIV, 0);
                        blocksList.Add(BitConverter.GetBytes(xorResult));
                        IV += delta;
                        copyIV = BitConverter.GetBytes(IV);
                    }

                    break;
                }

                case EncryptionMode.RDH:
                {
                    var curBlock = new byte[RC6Utils.BlockSize];
                    var copyIV = new byte[8];
                    var delta = BitConverter.ToUInt64(_initializationVector);
                    Array.Copy(block, 0, curBlock, 0, RC6Utils.BlockSize);
                    copyIV = Encrypter.Decrypt(curBlock);
                    var IV = BitConverter.ToUInt64(copyIV);
                    Array.Copy(block, 8, curBlock, 0, RC6Utils.BlockSize);
                    var xorResult = BitConverter.ToUInt64(copyIV)
                                    ^ BitConverter.ToUInt64(
                                        PaddingPkcs7(BitConverter.GetBytes(_strParam.GetHashCode())));
                    for (var i = 2; i < block.Length / RC6Utils.BlockSize; ++i)
                    {
                        IV += delta;
                        copyIV = BitConverter.GetBytes(IV);
                        Array.Copy(block, i * RC6Utils.BlockSize, curBlock, 0, RC6Utils.BlockSize);
                        xorResult = BitConverter.ToUInt64(Encrypter.Decrypt(curBlock)) ^ BitConverter.ToUInt64(copyIV);
                        blocksList.Add(BitConverter.GetBytes(xorResult));
                    }

                    break;
                }

                default:
                    throw new ArgumentOutOfRangeException(nameof(_mode), "Incorrect mode");
            }

            var connectedBlock = new byte[blocksList.Count * RC6Utils.BlockSize];
            for (var i = 0; i < blocksList.Count; ++i)
            {
                Array.Copy(blocksList[i], 0, connectedBlock,
                    i * RC6Utils.BlockSize, RC6Utils.BlockSize);
            }

            var returnBlock = new byte[connectedBlock.Length - _cutSize];
            Array.Copy(connectedBlock, returnBlock, returnBlock.Length);
            return returnBlock;
        }
    }
}