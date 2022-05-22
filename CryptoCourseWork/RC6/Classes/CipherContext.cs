using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Runtime.CompilerServices;

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
    }
    
    public sealed class CipherContext
    {
        public ICrypto Encrypter { get; set; }
        private byte[] _initializationVector;
        private readonly EncryptionMode _mode;
        private readonly string _param;
        
        public CipherContext(EncryptionMode mode, byte[] vector = null, string param = null)
        {
            _mode = mode;
            _initializationVector = vector;
            _param = param;
        }
        
        private static byte[] Xor(byte[] leftBlock, byte[] rightBlock)
        {
            var resultBlock = new byte[leftBlock.Length];
            for (var i = 0; i < Math.Min(leftBlock.Length, rightBlock.Length); ++i)
            {
                resultBlock[i] = (byte)(leftBlock[i] ^ rightBlock[i]);
            }
            return resultBlock;
        }
        
        private static byte[] PaddingPkcs7(byte[] block)
        {
            byte mod = (byte)(RC6Utils.BlockSize - block.Length % RC6Utils.BlockSize);
            byte[] paddedData = new byte[block.Length + mod];
            Array.Copy(block, paddedData, block.Length);
            Array.Fill(paddedData, mod, block.Length, mod);
            return paddedData;
        }
        
        private static byte[] ListToByteArray(List<byte[]> blocksList)
        {
            var resultBlock = new byte[RC6Utils.BlockSize * blocksList.Count];
            for (var i = 0; i < blocksList.Count; ++i)
            {
                Array.Copy(blocksList[i], 0, resultBlock,
                    i * RC6Utils.BlockSize, RC6Utils.BlockSize);
            }
            return resultBlock;
        }
        
        public byte[] Encrypt(byte[] block)
        {
            var paddedBlock = PaddingPkcs7(block); 
            var encryptedBlocksList = new List<byte[]>();
            switch (_mode)
            {
                case EncryptionMode.ECB:
                {
                    var currBlock = new byte[RC6Utils.BlockSize];
                    for (var i = 0; i < paddedBlock.Length / RC6Utils.BlockSize; ++i)
                    {
                        Array.Copy(paddedBlock, i * RC6Utils.BlockSize, currBlock,
                            0, RC6Utils.BlockSize);
                        encryptedBlocksList.Add(Encrypter.Encrypt(currBlock));
                    }
                    break;
                }
                
                case EncryptionMode.CBC:
                {
                    var prevBlock = new byte[RC6Utils.BlockSize];
                    var currBlock = new byte[RC6Utils.BlockSize];
                    Array.Copy(_initializationVector, prevBlock, prevBlock.Length);
                    for (var i = 0; i < paddedBlock.Length / RC6Utils.BlockSize; ++i)
                    {
                        Array.Copy(paddedBlock, i * RC6Utils.BlockSize, currBlock, 
                            0, RC6Utils.BlockSize);
                        encryptedBlocksList.Add(Encrypter.Encrypt(Xor(currBlock, prevBlock)));
                        Array.Copy(encryptedBlocksList[i], prevBlock, RC6Utils.BlockSize);
                    }
                    break;
                }
                
                case EncryptionMode.CFB:
                {
                    var prevBlock = new byte[RC6Utils.BlockSize];
                    var currBlock = new byte[RC6Utils.BlockSize];
                    Array.Copy(_initializationVector, prevBlock, prevBlock.Length);
                    for (var i = 0; i < paddedBlock.Length / RC6Utils.BlockSize; ++i)
                    {
                        Array.Copy(paddedBlock, i * RC6Utils.BlockSize, currBlock,
                            0, RC6Utils.BlockSize);
                        encryptedBlocksList.Add(Xor(Encrypter.Encrypt(prevBlock), currBlock));
                        Array.Copy(encryptedBlocksList[i], prevBlock, RC6Utils.BlockSize);
                    }
                    break;
                }
                
                case EncryptionMode.OFB:
                {
                    var prevBlock = new byte[RC6Utils.BlockSize];
                    var currBlock = new byte[RC6Utils.BlockSize];
                    Array.Copy(_initializationVector, prevBlock, prevBlock.Length);
                    for (var i = 0; i < paddedBlock.Length / RC6Utils.BlockSize; ++i)
                    {
                        Array.Copy(paddedBlock, i * RC6Utils.BlockSize, currBlock, 
                            0, RC6Utils.BlockSize);
                        var encryptedBlock = Encrypter.Encrypt(prevBlock);
                        encryptedBlocksList.Add(Xor(encryptedBlock, currBlock));
                        Array.Copy(encryptedBlock, prevBlock, RC6Utils.BlockSize);
                    }
                    break;
                }
                
                case EncryptionMode.CTR:
                {
                    var copyIV = new byte[_initializationVector.Length];
                    _initializationVector.CopyTo(copyIV, 0);
                    var counter = new BigInteger(copyIV);
                    var currBlock = new byte[RC6Utils.BlockSize];
                    for (var i = 0; i < paddedBlock.Length / RC6Utils.BlockSize; ++i)
                    {
                        Array.Copy(paddedBlock, i * RC6Utils.BlockSize, currBlock,
                            0, RC6Utils.BlockSize);
                        encryptedBlocksList.Add(Xor(Encrypter.Encrypt(copyIV), currBlock));
                        counter++;
                        copyIV = counter.ToByteArray();
                    }
                    break;
                }
                
                case EncryptionMode.RD:
                {
                    var currBlock = new byte[RC6Utils.BlockSize];
                    var copyIV = new byte[_initializationVector.Length];
                    Array.Copy(_initializationVector, 0, copyIV, 
                        0, RC6Utils.BlockSize);
                    var IV =  new BigInteger(copyIV);
                    var delta = new BigInteger(_initializationVector);
                    encryptedBlocksList.Add(Encrypter.Encrypt(copyIV));
                    for (var i = 0; i < paddedBlock.Length / RC6Utils.BlockSize; ++i)
                    {
                        Array.Copy(paddedBlock, i * RC6Utils.BlockSize, currBlock,
                            0, RC6Utils.BlockSize);
                        encryptedBlocksList.Add(Encrypter.Encrypt(Xor(copyIV, currBlock)));
                        IV += delta;
                        copyIV = IV.ToByteArray();
                    }
                    break;
                }
                
                case EncryptionMode.RDH:
                {
                    var currBlock = new byte[RC6Utils.BlockSize];
                    var copyIV = new byte[_initializationVector.Length];
                    Array.Copy(_initializationVector, 0, copyIV, 
                        0, RC6Utils.BlockSize);
                    var IV = new BigInteger(copyIV);
                    var delta = new BigInteger(_initializationVector);
                    encryptedBlocksList.Add(Encrypter.Encrypt(copyIV));
                    encryptedBlocksList.Add(Xor(copyIV, PaddingPkcs7(BitConverter.GetBytes(_param.GetHashCode()))));
                    for (var i = 0; i < paddedBlock.Length / RC6Utils.BlockSize; ++i)
                    {
                        IV += delta;
                        copyIV = IV.ToByteArray();
                        Array.Copy(paddedBlock, i * RC6Utils.BlockSize, currBlock, 
                            0, RC6Utils.BlockSize);
                        encryptedBlocksList.Add(Encrypter.Encrypt(Xor(copyIV, currBlock)));
                    }
                    break;
                }
                
                default:
                    throw new ArgumentOutOfRangeException(nameof(_mode));
            }
            return ListToByteArray(encryptedBlocksList);
        }

        public byte[] Decrypt(byte[] block)
        {
            var decryptedBlocksList = new List<byte[]>();
            switch (_mode)
            {
                case EncryptionMode.ECB:
                {
                    var currBlock = new byte[RC6Utils.BlockSize];
                    for (var i = 0; i < block.Length / RC6Utils.BlockSize; ++i)
                    {
                        Array.Copy(block, i * RC6Utils.BlockSize, currBlock,
                            0, RC6Utils.BlockSize);
                        decryptedBlocksList.Add(Encrypter.Decrypt(currBlock));
                    }
                    break;
                }
                
                case EncryptionMode.CBC:
                {
                    var prevBlock = new byte[RC6Utils.BlockSize];
                    var currBlock = new byte[RC6Utils.BlockSize];
                    Array.Copy(_initializationVector, prevBlock, prevBlock.Length);
                    for (var i = 0; i < block.Length / RC6Utils.BlockSize; ++i)
                    {
                        Array.Copy(block, i * RC6Utils.BlockSize, currBlock, 
                            0, RC6Utils.BlockSize);
                        decryptedBlocksList.Add(Xor(prevBlock, Encrypter.Decrypt(currBlock)));
                        Array.Copy(currBlock, prevBlock, RC6Utils.BlockSize);
                    }
                    break;
                }
                
                case EncryptionMode.CFB:
                {
                    var prevBlock = new byte[RC6Utils.BlockSize];
                    var currBlock = new byte[RC6Utils.BlockSize];
                    Array.Copy(_initializationVector, prevBlock, prevBlock.Length);
                    for (var i = 0; i < block.Length / RC6Utils.BlockSize; ++i)
                    {
                        Array.Copy(block, i * RC6Utils.BlockSize, currBlock, 
                            0, RC6Utils.BlockSize);
                        decryptedBlocksList.Add(Xor(Encrypter.Encrypt(prevBlock), currBlock));
                        Array.Copy(currBlock, prevBlock, RC6Utils.BlockSize);
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
                        var encryptedBlock = Encrypter.Encrypt(prevBlock);
                        decryptedBlocksList.Add(Xor(encryptedBlock, curBlock));
                        Array.Copy(encryptedBlock, prevBlock, RC6Utils.BlockSize);
                    }
                    break;
                }
                
                case EncryptionMode.CTR:
                {
                    var counter = new BigInteger(_initializationVector);
                    var currBlock = new byte[RC6Utils.BlockSize];
                    for (var i = 0; i < block.Length / RC6Utils.BlockSize; ++i)
                    {
                        Array.Copy(block, i * RC6Utils.BlockSize, currBlock, 
                            0, RC6Utils.BlockSize);
                        decryptedBlocksList.Add(Xor(Encrypter.Encrypt(_initializationVector), currBlock));
                        counter++;
                        _initializationVector = counter.ToByteArray();
                    }
                    break;
                }
                
                case EncryptionMode.RD:
                {
                    var currBlock = new byte[RC6Utils.BlockSize];
                    var copyIV = new byte[_initializationVector.Length];
                    var delta = new BigInteger(_initializationVector);
                    Array.Copy(block, 0, currBlock, 
                        0, RC6Utils.BlockSize);
                    copyIV = Encrypter.Decrypt(currBlock);
                    var IV = new BigInteger(copyIV);
                    for (var i = 1; i < block.Length / RC6Utils.BlockSize; ++i)
                    {
                        Array.Copy(block, i * RC6Utils.BlockSize, currBlock, 
                            0, RC6Utils.BlockSize);
                        decryptedBlocksList.Add(Xor(Encrypter.Decrypt(currBlock), copyIV));
                        IV += delta;
                        copyIV = IV.ToByteArray();
                    }
                    break;
                }
                
                case EncryptionMode.RDH:
                {
                    var currBlock = new byte[RC6Utils.BlockSize];
                    var copyIV = new byte[_initializationVector.Length];
                    var delta = new BigInteger(_initializationVector);
                    Array.Copy(block, 0, currBlock, 0, RC6Utils.BlockSize);
                    copyIV = Encrypter.Decrypt(currBlock);
                    var IV = new BigInteger(copyIV);
                    Array.Copy(block, RC6Utils.BlockSize, currBlock, 
                        0, RC6Utils.BlockSize);
                    if (!Xor(copyIV, PaddingPkcs7(BitConverter.GetBytes(_param.GetHashCode()))).SequenceEqual(currBlock))
                        break;

                    for (int i = 2; i < block.Length / RC6Utils.BlockSize; i++)
                    {
                        IV += delta;
                        copyIV = IV.ToByteArray();
                        Array.Copy(block, i * RC6Utils.BlockSize, currBlock, 
                            0, RC6Utils.BlockSize);
                        decryptedBlocksList.Add(Xor(Encrypter.Decrypt(currBlock), copyIV));
                    }
                    break;
                }
                
                default:
                    throw new ArgumentOutOfRangeException(nameof(_mode), "");
            }
            var connectedBlocks = ListToByteArray(decryptedBlocksList); 
            var resultBlock = new byte[connectedBlocks.Length - connectedBlocks[^1]];
            Array.Copy(connectedBlocks, resultBlock, resultBlock.Length);
            return resultBlock;
        }
    }
}