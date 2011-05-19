using System;
using System.IdentityModel.Tokens;
using System.IO;
using System.Text;

namespace Talk2Bits.IdentityModel.OAuth
{
    internal class JwtIssuer : OAuthIssuer, IOAuthIssuerContract
    {
        protected override string TokenTypeIdentifier
        {
            get { return JwtSecurityTokenHandler.TokenTypeIdentifier; }
        }

        protected override void WriteToken(Stream response, SecurityToken token)
        {
            var jwt = (JsonWebToken)token;
            var buffer = Encoding.ASCII.GetBytes(jwt.GetRawToken());
            response.Write(buffer, 0, buffer.Length);
        }
    }
}