using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Utility
{
    /// <summary>
	/// 使用DES(数据加密算法)对数据进行加密/解密的类
	/// </summary>
	public sealed class DESHelper
    {
        /// <summary>
        /// 加密密钥
        /// </summary>
        public const string SECRET = "L82V6ZVD6J";

        private static byte[] Keys = new byte[]
        {
            18,
            52,
            86,
            120,
            144,
            171,
            205,
            239
        };

        /// <summary>
        /// DES加密字符串
        /// </summary>
        /// <param name="encryptString">待加密的字符串</param>
        /// <param name="encryptKey">加密密钥,要求为8位</param>
        /// <returns>加密成功返回加密后的字符串,失败返回源串</returns>
        public static string Encode(string encryptString, string encryptKey)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(encryptKey.Substring(0, 8));
            byte[] keys = DESHelper.Keys;
            byte[] bytes2 = Encoding.UTF8.GetBytes(encryptString);
            string result;
            try
            {
                DESCryptoServiceProvider dESCryptoServiceProvider = new DESCryptoServiceProvider();
                MemoryStream expr_30 = new MemoryStream();
                CryptoStream expr_3F = new CryptoStream(expr_30, dESCryptoServiceProvider.CreateEncryptor(bytes, keys), CryptoStreamMode.Write);
                expr_3F.Write(bytes2, 0, bytes2.Length);
                expr_3F.FlushFinalBlock();
                result = Convert.ToBase64String(expr_30.ToArray());
            }
            catch
            {
                result = string.Empty;
            }
            return result;
        }

        /// <summary>
        /// DES解密字符串
        /// </summary>
        /// <param name="decryptString">待解密的字符串</param>
        /// <param name="decryptKey">解密密钥,要求为8位,和加密密钥相同</param>
        /// <returns>解密成功返回解密后的字符串,失败返源串</returns>
        public static string Decode(string decryptString, string decryptKey)
        {
            string result;
            try
            {
                byte[] bytes = Encoding.UTF8.GetBytes(decryptKey.Substring(0, 8));
                byte[] keys = DESHelper.Keys;
                byte[] array = Convert.FromBase64String(decryptString);
                DESCryptoServiceProvider dESCryptoServiceProvider = new DESCryptoServiceProvider();
                MemoryStream memoryStream = new MemoryStream();
                CryptoStream expr_3D = new CryptoStream(memoryStream, dESCryptoServiceProvider.CreateDecryptor(bytes, keys), CryptoStreamMode.Write);
                expr_3D.Write(array, 0, array.Length);
                expr_3D.FlushFinalBlock();
                result = Encoding.UTF8.GetString(memoryStream.ToArray());
            }
            catch
            {
                try
                {
                    decryptString = UrlHelper.UrlDecode(decryptString);
                    byte[] bytes2 = Encoding.UTF8.GetBytes(decryptKey.Substring(0, 8));
                    byte[] keys2 = DESHelper.Keys;
                    byte[] array2 = Convert.FromBase64String(decryptString);
                    DESCryptoServiceProvider dESCryptoServiceProvider2 = new DESCryptoServiceProvider();
                    MemoryStream memoryStream2 = new MemoryStream();
                    CryptoStream expr_AF = new CryptoStream(memoryStream2, dESCryptoServiceProvider2.CreateDecryptor(bytes2, keys2), CryptoStreamMode.Write);
                    expr_AF.Write(array2, 0, array2.Length);
                    expr_AF.FlushFinalBlock();
                    result = Encoding.UTF8.GetString(memoryStream2.ToArray());
                }
                catch
                {
                    result = string.Empty;
                }
            }
            return result;
        }
    }
}
