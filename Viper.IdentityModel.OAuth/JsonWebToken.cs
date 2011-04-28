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
        public List<SecurityKey> _keys = new List<SecurityKey>();

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

        public JsonWebToken(
            JwtHeaderSegment header, 
            JwtClaimsSegment claims,
            SecurityKey signingKey)
        {
            if (header == null)
                throw new ArgumentNullException("header");
            if (claims == null)
                throw new ArgumentNullException("claims");
            if (signingKey == null)
                throw new ArgumentNullException("signingKey");

            HeaderSection = header;
            ClaimsSection = claims;
            _keys.Add(signingKey);
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
            get { return _keys.AsReadOnly(); }
        }

        internal string GetJwsHeaderInput()
        {
            var decodedJwsHeaderInput = Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(HeaderSection));
            return JwtTokenUtility.Base64UrlEncode(decodedJwsHeaderInput);
        }

        internal string GetJwsPayloadInput()
        {
            var decodedJwsPayloadInput = Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(ClaimsSection));
            return JwtTokenUtility.Base64UrlEncode(decodedJwsPayloadInput);
        }
    }
}