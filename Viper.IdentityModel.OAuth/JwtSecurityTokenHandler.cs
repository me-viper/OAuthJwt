using System;
using System.IdentityModel.Tokens;
using System.Security.Cryptography;
using System.Text;
using System.Xml;
using Microsoft.IdentityModel.Claims;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;

namespace Viper.IdentityModel.OAuth
{
    public class JwtSecurityTokenHandler : SecurityTokenHandler
    {
        public const string TokenTypeIdentifier = "http://openid.net/specs/jwt/1.0";

        public override Type TokenType
        {
            get { return typeof(JsonWebToken); }
        }

        public override bool CanWriteToken
        {
            get { return true; }
        }

        public override bool CanValidateToken
        {
            get { return true; }
        }

        public override string[] GetTokenTypeIdentifiers()
        {
            return new [] { TokenTypeIdentifier };
        }

        public override bool CanReadToken(XmlReader reader)
        {
            return reader.IsStartElement("BinarySecurityToken", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd") &&
                reader.GetAttribute("ValueType") == "http://schemas.xmlsoap.org/ws/2009/11/jwt-token-profile-1.0";
        }

        public override SecurityToken ReadToken(XmlReader reader)
        {
            if (!CanReadToken(reader))
                throw new InvalidOperationException("Invalid token.");

            var buffer = reader.ReadContentAsString();

            return JsonWebToken.ParseRawToken(buffer);
        }

        public override ClaimsIdentityCollection ValidateToken(SecurityToken token)
        {
            var jwt = (JsonWebToken)token;

            // ! Resolve signing key here !
            var key = new InMemorySymmetricSecurityKey(null);
            var mac = new HMACSHA256(key.GetSymmetricKey());
            
            var cryptoInput = JwtTokenUtility.Base64UrlEncode(
                mac.ComputeHash(Encoding.UTF8.GetBytes(jwt.GetSigningInput()))
                );

            if (!string.Equals(jwt.Signature, cryptoInput, StringComparison.Ordinal))
                throw new InvalidOperationException("Token contents do not match signature.");

            // TODO: Expiration validation.
            // TODO: Issuer validation.
            // TODO: Audience uri validation.

            var inputIdentity = new ClaimsIdentity(jwt.ClaimsSection.Claims);

            return new ClaimsIdentityCollection(new [] {inputIdentity});
        }

        public override void WriteToken(XmlWriter writer, SecurityToken token)
        {
            if (token == null)
                throw new ArgumentNullException("token");

            var wrappedElement = JwtTokenUtility.WrapInsideBinarySecurityToken(
                ((JsonWebToken)token).GetRawToken()
                );

            wrappedElement.WriteTo(writer);
        }

        public override SecurityToken CreateToken(SecurityTokenDescriptor tokenDescriptor)
        {
            var seconds = (tokenDescriptor.Lifetime.Expires - tokenDescriptor.Lifetime.Created) ?? new TimeSpan(0, 0, 3600);
            var header = new JwtHeaderSegment();
            var claims = new JwtClaimsSegment(
                tokenDescriptor.TokenIssuerName,
                tokenDescriptor.AppliesToAddress,
                DateTime.UtcNow,
                DateTime.UtcNow + seconds,
                tokenDescriptor.Subject.Claims
                );

            var key = (InMemorySymmetricSecurityKey)tokenDescriptor.SigningCredentials.SigningKey;
            var mac = new HMACSHA256(key.GetSymmetricKey());
            var hash = mac.ComputeHash(Encoding.UTF8.GetBytes(JsonWebToken.GetSigningInput(header, claims)));
            var jwsCryptoOutput = JwtTokenUtility.Base64UrlEncode(hash);

            return new JsonWebToken(header, claims, jwsCryptoOutput);
        }
    }
}