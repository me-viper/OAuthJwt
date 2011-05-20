using System;
using System.IdentityModel.Tokens;

namespace Talk2Bits.IdentityModel.OAuth
{
    /// <summary>
    /// IP that issues JWT tokens.
    /// </summary>
    internal class JwtIssuer : OAuthIssuer, IOAuthIssuerContract
    {
        protected override string TokenTypeIdentifier
        {
            get { return JwtSecurityTokenHandler.TokenTypeIdentifier; }
        }

        protected override OAuthTokenResponse GetResponse(SecurityToken token)
        {
            var jwt = (JsonWebToken)token;

            var response = new OAuthTokenResponse
                {
                    AccessToken = jwt.GetRawToken(),
                    TokenType = "jwt",
                    ExpiresIn = jwt.ClaimsSection.ExpiresAt - jwt.ClaimsSection.IssuedAt
                };

            return response;
        }
    }
}