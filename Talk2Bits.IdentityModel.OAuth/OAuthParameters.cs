using System;

namespace Talk2Bits.IdentityModel.OAuth
{
    public static class OAuthParameters
    {
        public const string ClientId = "client_id";
        public const string ClientSecret = "client_secret";
        public const string UserName = "username";
        public const string Password = "password";
        public const string GrantType = "grant_type";
        public const string Scope = "scope";
    }

    public static class OAuthGrantTypes
    {
        public const string Password = "password";
    }
}