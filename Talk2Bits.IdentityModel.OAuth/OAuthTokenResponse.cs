using System;

using Newtonsoft.Json;

namespace Talk2Bits.IdentityModel.OAuth
{
    /// <summary>
    /// Security token format defined by OAuth v2 specification.
    /// </summary>
    [JsonObject(MemberSerialization.OptIn)]
    public class OAuthTokenResponse
    {
        [JsonProperty("access_token")]
        public string AccessToken { get; set; }

        [JsonProperty("token_type")]
        public string TokenType { get; set; }

        [JsonProperty("expires_in", DefaultValueHandling = DefaultValueHandling.Ignore)]
        public long ExpiresIn { get; set; }

        [JsonProperty("refresh_token", DefaultValueHandling = DefaultValueHandling.Ignore)]
        public string RefreshToken { get; set; }

        internal bool Validate()
        {
            return !string.IsNullOrWhiteSpace(AccessToken) && !string.IsNullOrWhiteSpace(TokenType);
        }
    }
}