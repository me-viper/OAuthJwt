using System;
using System.Collections.Generic;

using Microsoft.IdentityModel.Claims;

using Newtonsoft.Json;

namespace Talk2Bits.IdentityModel.OAuth
{
    [JsonObject(MemberSerialization.OptIn)]
    public class JwtClaimsSegment
    {
        private List<Claim> _claims;

        public JwtClaimsSegment(
            string issuer, 
            string audience, 
            DateTime validFrom,
            DateTime validTo,
            IEnumerable<Claim> claims)
        {
            Issuer = issuer;
            Audience = audience;
            _claims = new List<Claim>(claims);

            IssuedAt = (long)(validFrom - new DateTime(1970, 1, 1)).TotalSeconds;
            ExpiresAt = (long)(validTo - new DateTime(1970, 1, 1)).TotalSeconds;
        }

        [JsonProperty("iss")]
        public string Issuer { get; private set; }

        [JsonProperty("aud")]
        public string Audience { get; private set; }
        
        [JsonProperty("exp")]
        public long ExpiresAt { get; private set; }

        [JsonProperty("iat")]
        public long IssuedAt { get; private set; }

        // TODO: Apparently that should be ReadOnlyCollection.
        [JsonProperty("http://schemas.bradycorp.com/2010/03/jwt/claims")]
        [JsonConverter(typeof(JsonClaimsConverterCollection))]
        public ICollection<Claim> Claims
        {
            get { return _claims; }
            private set { _claims = new List<Claim>(value); }
        }
    }
}