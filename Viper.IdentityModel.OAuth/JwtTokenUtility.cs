using System;
using System.Xml.Linq;

namespace Viper.IdentityModel.OAuth
{
    public class JwtTokenUtility
    {
        public static string Base64UrlEncode(byte[] arg)
        {
            // Standard base64 encoder.
            var s = Convert.ToBase64String(arg);

            s = s.Split('=')[0]; // Remove any trailing '='s.
            s = s.Replace('+', '-'); // 62nd char of encoding.
            s = s.Replace('/', '_'); // 63rd char of encoding.

            return s;
        }

        public static byte[] Base64UrlDecode(string arg)
        {
            string s = arg;

            s = s.Replace('-', '+'); // 62nd char of encoding
            s = s.Replace('_', '/'); // 63rd char of encoding

            switch (s.Length % 4) // Pad with trailing '='s
            {
                case 0: break; // No pad chars in this case
                case 2: s += "=="; break; // Two pad chars
                case 3: s += "="; break; // One pad char
                default: throw new Exception("Illegal base64url string!");
            }

            return Convert.FromBase64String(s); // Standard base64 decoder
        }

        public static XElement WrapInsideBinarySecurityToken(string accessToken)
        {
            var root = new XElement(
                XNamespace.Get("http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd").GetName("BinarySecurityToken"),
                new XAttribute("ValueType", "http://schemas.xmlsoap.org/ws/2009/11/jwt-token-profile-1.0"),
                new XAttribute("EncodingType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary"),
                accessToken
                );

            return root;
        }
    }
}