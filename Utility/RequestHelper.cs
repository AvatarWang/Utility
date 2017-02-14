using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace System.Web
{
    /// <summary>
    /// HttpRequest的拓展方法
    /// </summary>
    public static class RequestHelper
    {
        /// <summary>
        /// 判断当前请求是否是POST请求
        /// </summary>
        /// <param name="request"></param>
        /// <returns></returns>
        public static bool IsPostBack(this HttpRequest request)
        {
            return "post".Equals(request.HttpMethod, StringComparison.InvariantCultureIgnoreCase);
        }

        /// <summary>
        /// 获取请求参数中的Int类型值
        /// </summary>
        /// <param name="request"></param>
        /// <param name="key"></param>
        /// <param name="def"></param>
        /// <returns></returns>
        public static int GetInt(this HttpRequest request, string key, int def = 0)
        {
            int res;
            var temp = request[key];
            if (int.TryParse(temp, out res))
            {
                return res;
            }
            return def;
        }
    }
}
