using System;
using System.Collections.Generic;
using System.Linq;
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
        public ICrypto Encrypter;
        private readonly EncryptionMode _mode;
        private byte[] _initializationVector;
        private readonly string _param;
        
        public CipherContext(EncryptionMode mode, byte[] vector = null, string param = null)
        {
            _mode = mode;
            _initializationVector = vector;
            _param = param;
        }
        
        private byte[] PaddingPKCS7(byte[] data)
        {
            byte mod = (byte)(RC6Utils.BlockSize - data.Length % RC6Utils.BlockSize);
            byte[] paddedData = new byte[data.Length + mod];
            Array.Copy(data, paddedData, data.Length);
            Array.Fill(paddedData, mod, data.Length, mod);
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

        private static byte[] Xor(byte[] left, byte[] right)
        {
            var resultBlock = new byte[left.Length];
            for (var i = 0; i < Math.Min(left.Length, right.Length); ++i)
            {
                resultBlock[i] = (byte)(left[i] ^ right[i]);
            }
            return resultBlock;
        }
        
        public byte[] Encrypt(byte[] data)
        {
            var paddedBlock = PaddingPKCS7(data); 
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
                    var copyIV = new byte[RC6Utils.BlockSize];
                    _initializationVector.CopyTo(copyIV, 0);
                    var counter = BitConverter.ToUInt64(copyIV);
                    var currBlock = new byte[RC6Utils.BlockSize];
                    for (var i = 0; i < paddedBlock.Length / RC6Utils.BlockSize; ++i)
                    {
                        Array.Copy(paddedBlock, i * RC6Utils.BlockSize, currBlock,
                            0, RC6Utils.BlockSize);
                        encryptedBlocksList.Add(Xor(Encrypter.Encrypt(copyIV), currBlock));
                        counter++;
                        copyIV = BitConverter.GetBytes(counter);
                    }
                    break;
                }
                
                case EncryptionMode.RD:
                {
                    var currBlock = new byte[RC6Utils.BlockSize];
                    var copyIV = new byte[RC6Utils.BlockSize];
                    Array.Copy(_initializationVector, 0, copyIV, 
                        0, RC6Utils.BlockSize);
                    var IV = BitConverter.ToUInt64(copyIV);
                    var delta = BitConverter.ToUInt64(_initializationVector);
                    encryptedBlocksList.Add(Encrypter.Encrypt(copyIV));
                    for (var i = 0; i < paddedBlock.Length / RC6Utils.BlockSize; ++i)
                    {
                        Array.Copy(paddedBlock, i * RC6Utils.BlockSize, currBlock,
                            0, RC6Utils.BlockSize);
                        encryptedBlocksList.Add(Encrypter.Encrypt(Xor(copyIV, currBlock)));
                        IV += delta;
                        copyIV = BitConverter.GetBytes(IV);
                    }
                    break;
                }
                
                case EncryptionMode.RDH:
                {
                    var currBlock = new byte[RC6Utils.BlockSize];
                    var copyIV = new byte[RC6Utils.BlockSize];
                    Array.Copy(_initializationVector, 0, copyIV, 
                        0, RC6Utils.BlockSize);
                    var IV = BitConverter.ToUInt64(copyIV);
                    var delta = BitConverter.ToUInt64(_initializationVector);
                    encryptedBlocksList.Add(Encrypter.Encrypt(copyIV));
                    encryptedBlocksList.Add(Xor(copyIV, PaddingPKCS7(BitConverter.GetBytes(_param.GetHashCode()))));
                    for (var i = 0; i < paddedBlock.Length / RC6Utils.BlockSize; ++i)
                    {
                        IV += delta;
                        copyIV = BitConverter.GetBytes(IV);
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

        public byte[] Decrypt(byte[] data)
        {
            var decryptedBlocksList = new List<byte[]>();
            switch (_mode)
            {
                case EncryptionMode.ECB:
                {
                    var currBlock = new byte[RC6Utils.BlockSize];
                    for (var i = 0; i < data.Length / RC6Utils.BlockSize; ++i)
                    {
                        Array.Copy(data, i * RC6Utils.BlockSize, currBlock,
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
                    for (var i = 0; i < data.Length / RC6Utils.BlockSize; ++i)
                    {
                        Array.Copy(data, i * RC6Utils.BlockSize, currBlock, 
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
                    for (var i = 0; i < data.Length / RC6Utils.BlockSize; ++i)
                    {
                        Array.Copy(data, i * RC6Utils.BlockSize, currBlock, 
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
                    for (var i = 0; i < data.Length / RC6Utils.BlockSize; ++i)
                    {
                        Array.Copy(data, i * RC6Utils.BlockSize, curBlock, 
                            0, RC6Utils.BlockSize);
                        var encryptedBlock = Encrypter.Encrypt(prevBlock);
                        decryptedBlocksList.Add(Xor(encryptedBlock, curBlock));
                        Array.Copy(encryptedBlock, prevBlock, RC6Utils.BlockSize);
                    }
                    break;
                }
                
                case EncryptionMode.CTR:
                {
                    var counter = BitConverter.ToUInt64(_initializationVector);
                    var currBlock = new byte[RC6Utils.BlockSize];
                    for (var i = 0; i < data.Length / RC6Utils.BlockSize; ++i)
                    {
                        Array.Copy(data, i * RC6Utils.BlockSize, currBlock, 
                            0, RC6Utils.BlockSize);
                        decryptedBlocksList.Add(Xor(Encrypter.Encrypt(_initializationVector), currBlock));
                        counter++;
                        _initializationVector = BitConverter.GetBytes(counter);
                    }
                    break;
                }
                
                case EncryptionMode.RD:
                {
                    var currBlock = new byte[RC6Utils.BlockSize];
                    var copyIV = new byte[RC6Utils.BlockSize];
                    var delta = BitConverter.ToUInt64(_initializationVector);
                    Array.Copy(data, 0, currBlock, 
                        0, RC6Utils.BlockSize);
                    copyIV = Encrypter.Decrypt(currBlock);
                    var IV = BitConverter.ToUInt64(copyIV);
                    for (var i = 1; i < data.Length / RC6Utils.BlockSize; ++i)
                    {
                        Array.Copy(data, i * RC6Utils.BlockSize, currBlock, 
                            0, RC6Utils.BlockSize);
                        decryptedBlocksList.Add(Xor(Encrypter.Decrypt(currBlock), copyIV));
                        IV += delta;
                        copyIV = BitConverter.GetBytes(IV);
                    }
                    break;
                }
                
                case EncryptionMode.RDH:
                {
                    var currBlock = new byte[RC6Utils.BlockSize];
                    var copyIV = new byte[RC6Utils.BlockSize];
                    var delta = BitConverter.ToUInt64(_initializationVector);
                    Array.Copy(data, 0, currBlock, 
                        0, RC6Utils.BlockSize);
                    copyIV = Encrypter.Decrypt(currBlock);
                    var IV = BitConverter.ToUInt64(copyIV);
                    Array.Copy(data, RC6Utils.BlockSize, currBlock, 
                        0, RC6Utils.BlockSize);
                    if (!Xor(copyIV, PaddingPKCS7(BitConverter.GetBytes(_param.GetHashCode()))).SequenceEqual(currBlock))
                        break;

                    for (var i = 2; i < data.Length / RC6Utils.BlockSize; ++i)
                    {
                        IV += delta;
                        copyIV = BitConverter.GetBytes(IV);
                        Array.Copy(data, i * RC6Utils.BlockSize, currBlock, 
                            0, RC6Utils.BlockSize);
                        decryptedBlocksList.Add(Xor(Encrypter.Decrypt(currBlock), copyIV));
                    }
                    break;
                }
                
                default:
                    throw new ArgumentOutOfRangeException(nameof(_mode));
            }
            var connectedBlocks = ListToByteArray(decryptedBlocksList); 
            var resultBlock = new byte[connectedBlocks.Length - connectedBlocks[^1]];
            Array.Copy(connectedBlocks, resultBlock, resultBlock.Length);
            return resultBlock;
        }
    }
}