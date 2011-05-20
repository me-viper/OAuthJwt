using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IdentityModel.Tokens;
using System.Text;

using Newtonsoft.Json;

namespace Talk2Bits.IdentityModel.OAuth
{
    /// <summary>
    /// Represents Json Web Token.
    /// </summary>
    /// <remarks>
    /// Technically, this is just wrapper. Though this class
    /// has little value for JWT per se, we should comform to WIF requirements.
    /// </remarks>
    public class JsonWebToken : SecurityToken
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="JsonWebToken"/> class.
        /// </summary>
        /// <param name="header">The JWT header section.</param>
        /// <param name="claims">The JWT payload section.</param>
        /// <param name="signature">The JWT signature.</param>
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
            get { return (new List<SecurityKey>(0)).AsReadOnly(); }
        }

        /// <summary>
        /// Retrieves token signing input.
        /// </summary>
        /// <param name="header">JWT header section.</param>
        /// <param name="payload">JWT payload section.</param>
        /// <returns>Signing input.</returns>
        /// <remarks>For details refer to Json Web Signature specification.</remarks>
        internal static string GetSigningInput(JwtHeaderSegment header, JwtClaimsSegment payload)
        {
            var decodedJwsHeaderInput = Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(header));
            var jwsHeaderInput = JwtTokenUtility.Base64UrlEncode(decodedJwsHeaderInput);

            var decodedJwsPayloadInput = Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(payload));
            var jwsPaloadInput = JwtTokenUtility.Base64UrlEncode(decodedJwsPayloadInput);

            return string.Format("{0}.{1}", jwsHeaderInput, jwsPaloadInput);
        }

        /// <summary>
        /// Parses JWT.
        /// </summary>
        /// <param name="rawToken">Raw JWT encoded in base64 url encoding.</param>
        /// <returns>New instance of <see cref="JsonWebToken"/>.</returns>
        /// <remarks>For details refer to Json Web Token specification.</remarks>
        internal static JsonWebToken ParseRawToken(string rawToken)
        {
            JsonWebToken result = null;

            var tokenParts = rawToken.Split(new[] { "." }, StringSplitOptions.RemoveEmptyEntries);

            if (tokenParts.Length > 3 || tokenParts.Length < 2)
                throw new SecurityTokenException("Invalid token format.");

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
                throw new SecurityTokenException("Failed to parse token", ex);
            }

            return result;
        }

        /// <summary>
        /// Retrieves token signing input.
        /// </summary>
        /// <returns>Signing input.</returns>
        internal string GetSigningInput()
        {
            return GetSigningInput(HeaderSection, ClaimsSection);
        }

        /// <summary>
        /// Returs raw representation of JWT.
        /// </summary>
        /// <returns>Raw representation of JWT.</returns>
        internal string GetRawToken()
        {
            var signingInput = GetSigningInput();

            if (string.IsNullOrEmpty(Signature))
                return signingInput;

            return string.Format("{0}.{1}", signingInput, Signature);
        }
    }
}