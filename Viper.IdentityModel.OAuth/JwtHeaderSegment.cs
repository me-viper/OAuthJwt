using Newtonsoft.Json;

namespace Talk2Bits.IdentityModel.OAuth
{
    [JsonObject(MemberSerialization.OptIn)]
    public class JwtHeaderSegment
    {
        /// <summary>
        /// HMAC using SHA-256 hash algorithm.
        /// </summary>
        public const string HS256 = "HS256";

        public JwtHeaderSegment()
        {
            Type = JwtSecurityTokenHandler.TokenTypeIdentifier;
            Algorithm = HS256;
        }

        [JsonProperty("alg")]
        public string Algorithm { get; private set; }

        [JsonProperty("typ")]
        public string Type { get; private set; }
    }
}