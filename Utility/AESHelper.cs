using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Utility
{
    /// <summary>
    /// AES 加密类
    /// </summary>
    public class AESHelper
    {
        /// <summary>
        /// 默认密钥向量
        /// </summary>
        private static byte[] RijndaelIVValue = new byte[]
        {
            84,
            67,
            77,
            111,
            98,
            105,
            108,
            101,
            91,
            65,
            69,
            83,
            95,
            73,
            86,
            93
        };

        /// <summary>
        /// AES加密算法
        /// </summary>
        /// <param name="plainText">明文字符串</param>
        /// <param name="strRijnKey">密钥，必须为128位、192位或256位，默认选用128位</param>
        /// <returns>返回加密后的密文字节数组</returns>
        public static byte[] AESEncrypt(string plainText, string strRijnKey)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(strRijnKey);
            byte[] rijndaelIVValue = AESHelper.RijndaelIVValue;
            return AESHelper.AESEncrypt(plainText, bytes, rijndaelIVValue);
        }

        /// <summary>
        /// AES加密算法
        /// </summary>
        /// <param name="plainText">明文字符串</param>
        /// <param name="strRijnKey">密钥，必须为128位、192位或256位，默认选用128位</param>
        ///  <param name="strRijnIV">向量</param>
        /// <returns>返回加密后的密文字节数组</returns>
        public static byte[] AESEncrypt(string plainText, string strRijnKey, string strRijnIV)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(strRijnKey);
            byte[] bytes2 = Encoding.UTF8.GetBytes(strRijnIV);
            return AESHelper.AESEncrypt(plainText, bytes, bytes2);
        }

        /// <summary>
        /// AES加密算法
        /// </summary>
        /// <param name="plainText">明文字符串</param>
        /// <param name="rijnKey">密钥字节数组，必须为128位、192位或256位，默认选用128位</param>
        /// <param name="rijnIV">密钥初始化向量字节数组</param>
        /// <returns>返回加密后的密文字节数组</returns>
        public static byte[] AESEncrypt(string plainText, byte[] rijnKey, byte[] rijnIV)
        {
            SymmetricAlgorithm symmetricAlgorithm = null;
            MemoryStream memoryStream = null;
            CryptoStream cryptoStream = null;
            byte[] result;
            try
            {
                symmetricAlgorithm = Rijndael.Create();
                if (string.IsNullOrEmpty(plainText))
                {
                    plainText = string.Empty;
                }
                byte[] bytes = Encoding.UTF8.GetBytes(plainText);
                symmetricAlgorithm.Key = rijnKey;
                symmetricAlgorithm.IV = rijnIV;
                memoryStream = new MemoryStream();
                cryptoStream = new CryptoStream(memoryStream, symmetricAlgorithm.CreateEncryptor(), CryptoStreamMode.Write);
                cryptoStream.Write(bytes, 0, bytes.Length);
                cryptoStream.FlushFinalBlock();
                result = memoryStream.ToArray();
            }
            catch (Exception)
            {
                throw;
            }
            finally
            {
                if (symmetricAlgorithm != null)
                {
                    symmetricAlgorithm.Clear();
                }
                if (memoryStream != null)
                {
                    memoryStream.Flush();
                    memoryStream.Close();
                }
                if (cryptoStream != null)
                {
                    cryptoStream.Close();
                }
            }
            return result;
        }

        /// <summary>
        /// AES解密算法
        /// </summary>
        /// <param name="cipherText">密文字节数组</param>
        /// <param name="strRijnKey">密钥，必须为128位、192位或256位，默认选用128位</param>
        /// <returns>返回解密后的字符串</returns>
        public static string AESDecrypt(byte[] cipherText, string strRijnKey)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(strRijnKey);
            byte[] rijndaelIVValue = AESHelper.RijndaelIVValue;
            return AESHelper.AESDecrypt(cipherText, bytes, rijndaelIVValue);
        }

        /// <summary>
        /// AES解密算法
        /// </summary>
        /// <param name="cipherText">密文字节数组</param>
        /// <param name="rijnKey">密钥字节数组，必须为128位、192位或256位，默认选用128位</param>
        /// <param name="rijnIV">密钥初始化向量字节数组</param>
        /// <returns>返回解密后的字符串</returns>
        public static string AESDecrypt(byte[] cipherText, byte[] rijnKey, byte[] rijnIV)
        {
            SymmetricAlgorithm symmetricAlgorithm = null;
            MemoryStream memoryStream = null;
            CryptoStream cryptoStream = null;
            string result;
            try
            {
                symmetricAlgorithm = Rijndael.Create();
                symmetricAlgorithm.Key = rijnKey;
                symmetricAlgorithm.IV = rijnIV;
                memoryStream = new MemoryStream(cipherText);
                cryptoStream = new CryptoStream(memoryStream, symmetricAlgorithm.CreateDecryptor(), CryptoStreamMode.Read);
                result = new StreamReader(cryptoStream).ReadToEnd();
            }
            catch (Exception)
            {
                throw;
            }
            finally
            {
                if (symmetricAlgorithm != null)
                {
                    symmetricAlgorithm.Clear();
                }
                if (memoryStream != null)
                {
                    memoryStream.Flush();
                    memoryStream.Close();
                }
                if (cryptoStream != null)
                {
                    cryptoStream.Close();
                }
            }
            return result;
        }

        /// <summary>
        /// AES加密 ECB模式算法
        /// </summary>
        /// <param name="toEncrypt">需要加密的原文</param>
        /// <param name="key">加密的密钥（128位，196位，256位）</param>
        /// <returns>加密的密文</returns>
        public static byte[] ECBEncrypt(string toEncrypt, string key)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(key);
            byte[] bytes2 = Encoding.UTF8.GetBytes(toEncrypt);
            return new RijndaelManaged
            {
                KeySize = 128,
                Key = bytes,
                Mode = CipherMode.ECB,
                Padding = PaddingMode.Zeros
            }.CreateEncryptor().TransformFinalBlock(bytes2, 0, bytes2.Length);
        }

        /// <summary>
        /// AES加密 ECB模式算法
        /// 转Base64
        /// </summary>
        /// <param name="plainText">需要加密的密文</param>
        /// <param name="key"></param>
        /// <returns></returns>
        public static string ECBEncriptyToBase64(string plainText, string key)
        {
            byte[] array = AESHelper.ECBEncrypt(plainText, key);
            return Convert.ToBase64String(array, 0, array.Length);
        }

        /// <summary>
        /// AES解密 ECB模式算法
        /// </summary>
        /// <param name="toDecrypt">需要解密的密文</param>
        /// <param name="key">解密的密钥（128位，196位，256位）</param>
        /// <returns>解密的原文</returns>
        public static string ECBDecrypt(string toDecrypt, string key)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(key);
            byte[] array = Convert.FromBase64String(toDecrypt);
            byte[] bytes2 = new RijndaelManaged
            {
                KeySize = 128,
                Key = bytes,
                Mode = CipherMode.ECB,
                Padding = PaddingMode.Zeros
            }.CreateDecryptor().TransformFinalBlock(array, 0, array.Length);
            return Encoding.UTF8.GetString(bytes2);
        }
    }
}
