using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IdentityModel.Tokens;
using System.Text;

using Newtonsoft.Json;

namespace Viper.IdentityModel.OAuth
{
    public class JsonWebToken : SecurityToken
    {
        public JsonWebToken(
            JwtHeaderSegment header, 
            JwtClaimsSegment claims,
            string signature)
        {
            if (header == null)
                throw new ArgumentNullException("header");
            if (claims == null)
                throw new ArgumentNullException("claims");

            HeaderSection = header;
            ClaimsSection = claims;
            Signature = signature;
        }

        public JwtHeaderSegment HeaderSection { get; private set; }
        public JwtClaimsSegment ClaimsSection { get; private set; }
        public string Signature { get; private set; }

        public override string Id
        {
            get { throw new NotSupportedException(); }
        }

        public override DateTime ValidFrom
        {
            get { return new DateTime(1970, 1, 1, 0, 0, 0).AddSeconds(ClaimsSection.IssuedAt); }
        }

        public override DateTime ValidTo
        {
            get { return new DateTime(1970, 1, 1, 0, 0, 0).AddSeconds(ClaimsSection.ExpiresAt); }
        }

        public override ReadOnlyCollection<SecurityKey> SecurityKeys
        {
            get { return (new List<SecurityKey>()).AsReadOnly(); }
        }

        internal static string GetSigningInput(JwtHeaderSegment header, JwtClaimsSegment payload)
        {
            var decodedJwsHeaderInput = Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(header));
            var jwsHeaderInput = JwtTokenUtility.Base64UrlEncode(decodedJwsHeaderInput);

            var decodedJwsPayloadInput = Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(payload));
            var jwsPaloadInput = JwtTokenUtility.Base64UrlEncode(decodedJwsPayloadInput);

            return string.Format("{0}.{1}", jwsHeaderInput, jwsPaloadInput);
        }

        internal static JsonWebToken ParseRawToken(string rawToken)
        {
            JsonWebToken result = null;

            var tokenParts = rawToken.Split(new[] { "." }, StringSplitOptions.RemoveEmptyEntries);

            if (tokenParts.Length > 3 || tokenParts.Length < 2)
                throw new InvalidOperationException("Invalid token format.");

            var rawJwtHeader = Encoding.UTF8.GetString(JwtTokenUtility.Base64UrlDecode(tokenParts[0]));
            var rawJwtClaims = Encoding.UTF8.GetString(JwtTokenUtility.Base64UrlDecode(tokenParts[1]));
            var signature = tokenParts.Length > 2 ? tokenParts[2] : string.Empty;

            try
            {
                var headerSegment = JsonConvert.DeserializeObject<JwtHeaderSegment>(rawJwtHeader);
                var claimsSegment = JsonConvert.DeserializeObject<JwtClaimsSegment>(rawJwtClaims);

                result = new JsonWebToken(headerSegment, claimsSegment, signature);
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException("Failed to parse token", ex);
            }

            return result;
        }

        internal string GetSigningInput()
        {
            return GetSigningInput(HeaderSection, ClaimsSection);
        }

        internal string GetRawToken()
        {
            if (string.IsNullOrEmpty(Signature))
                return GetSigningInput(HeaderSection, ClaimsSection);

            return string.Format("{0}.{1}", GetSigningInput(HeaderSection, ClaimsSection), Signature);
        }
    }
}