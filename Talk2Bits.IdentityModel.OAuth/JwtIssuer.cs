using System;
using System.Collections.Specialized;
using System.IdentityModel.Tokens;
using System.IO;
using System.Text;

using Microsoft.IdentityModel.Protocols.WSTrust;
using Microsoft.IdentityModel.Tokens;

namespace Talk2Bits.IdentityModel.OAuth
{
    internal class JwtIssuer : OAuthIssuer, IOAuthIssuerContract
    {
        private SecurityToken _actAsToken;

        protected override string TokenTypeIdentifier
        {
            get { return JwtSecurityTokenHandler.TokenTypeIdentifier; }
        }

        protected override string GetTokenUsage()
        {
            if (_actAsToken != null)
                return SecurityTokenHandlerCollectionManager.Usage.ActAs;

            return base.GetTokenUsage();
        }

        protected override SecurityToken GetSecurityToken(NameValueCollection parameters, string grantType)
        {
            if (string.Equals(grantType, "http://oauth.net/grant_type/jwt/1.0/bearer", StringComparison.OrdinalIgnoreCase))
            {
                var rawToken = GetParameterOrThrow(parameters, "jwt");
                _actAsToken = JsonWebToken.ParseRawToken(rawToken);

                return _actAsToken;
            }

            return base.GetSecurityToken(parameters, grantType);
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

        protected override void PrepareRequestSecurityToken(RequestSecurityToken rst)
        {
            if (_actAsToken != null)
                rst.ActAs = new SecurityTokenElement(_actAsToken);

            base.PrepareRequestSecurityToken(rst);
        }
    }
}