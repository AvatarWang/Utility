using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Web;

namespace Utility
{
    public class UrlHelper
    {

        public static string UrlEncode(string str)
        {
            return HttpUtility.UrlEncode(str);
        }

        public static string UrlDecode(string str)
        {
            return HttpUtility.UrlDecode(str);
        }

        /// <summary>
        /// 图片后缀进行Http编码处理
        /// </summary>
        /// <param name="imageUrl">要进行http编码的图片URL</param>
        /// <returns></returns>
        public static string UrlEncodeImageSuffix(string imageUrl)
        {
            return UrlHelper.UrlEncodeImageSuffix("", imageUrl);
        }

        /// <summary>
        /// 图片后缀进行Http编码处理
        /// </summary>
        /// <param name="imageBaseUrl">图片基地址</param>
        /// <param name="imageUrl">要进行http编码的图片URL</param>
        /// <returns></returns>
        public static string UrlEncodeImageSuffix(string imageBaseUrl, string imageUrl)
        {
            string arg = imageUrl.Substring(0, imageUrl.LastIndexOf('/'));
            string text = imageUrl.Substring(imageUrl.LastIndexOf('/') + 1);
            text = HttpUtility.UrlEncode(text);
            if (text.Contains("+"))
            {
                text = text.Replace("+", "%20");
            }
            return imageBaseUrl + string.Format("{0}/{1}", arg, text);
        }

        public static string FullMathPath(string suffix)
        {
            if (string.IsNullOrWhiteSpace(suffix))
            {
                return string.Empty;
            }
            return HttpContext.Current.Server.MapPath(suffix);
        }

        /// <summary>
        /// 通过传入的url获取远程文件数据(二进制流)
        /// </summary>
        /// <param name="url">图片的URL</param>
        /// <param name="proxyServer">代理服务器</param>
        /// <returns>图片内容</returns>
        public static byte[] GetImgFile(string url, string proxyServer = "")
        {
            WebResponse webResponse = null;
            byte[] result = null;
            try
            {
                WebRequest webRequest = WebRequest.Create(new Uri(url));
                webResponse = webRequest.GetResponse();
                Stream responseStream = webResponse.GetResponseStream();
                if (!string.IsNullOrEmpty(proxyServer))
                {
                    webRequest.Proxy = new WebProxy(proxyServer);
                }
                using (MemoryStream memoryStream = new MemoryStream())
                {
                    int num;
                    while ((num = responseStream.ReadByte()) != -1)
                    {
                        memoryStream.WriteByte((byte)num);
                    }
                    result = memoryStream.ToArray();
                }
            }
            catch (Exception)
            {
                result = null;
            }
            finally
            {
                if (webResponse != null)
                {
                    webResponse.Close();
                }
            }
            return result;
        }
    }
}
