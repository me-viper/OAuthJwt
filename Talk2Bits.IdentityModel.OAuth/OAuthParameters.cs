using System;

namespace Talk2Bits.IdentityModel.OAuth
{
    /// <summary>
    /// Security token request parameters defined in OAuth v2 specification.
    /// </summary>
    public static class OAuthParameters
    {
        public const string ClientId = "client_id";
        public const string ClientSecret = "client_secret";
        public const string UserName = "username";
        public const string Password = "password";
        public const string GrantType = "grant_type";
        public const string Scope = "scope";
    }

    /// <summary>
    /// Grant types defined in OAuth v2 specification.
    /// </summary>
    public static class OAuthGrantTypes
    {
        public const string Password = "password";
    }
}