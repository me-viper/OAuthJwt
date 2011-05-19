using System;
using System.IdentityModel.Selectors;
using System.IdentityModel.Tokens;
using System.Net;
using System.Security.Cryptography;
using System.ServiceModel.Security;
using System.Text;
using System.Xml;

using Microsoft.IdentityModel.Claims;
using Microsoft.IdentityModel.Protocols.XmlSignature;
using Microsoft.IdentityModel.Tokens;

namespace Talk2Bits.IdentityModel.OAuth
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

            reader.Read();
            var buffer = reader.ReadContentAsString();

            return JsonWebToken.ParseRawToken(buffer);
        }

        public override ClaimsIdentityCollection ValidateToken(SecurityToken token)
        {
            if (token == null)
                throw new ArgumentNullException("token");

            var jwt = (JsonWebToken)token;
            InMemorySymmetricSecurityKey key = null;
            
            try
            {
                key = (InMemorySymmetricSecurityKey)Configuration.IssuerTokenResolver.ResolveSecurityKey(
                    new KeyNameIdentifierClause(jwt.ClaimsSection.Issuer)
                    );
            }
            catch (Exception)
            {
                throw new InvalidOperationException("Failed to resolver isser's key");
            }

            var mac = new HMACSHA256(key.GetSymmetricKey());
            
            var cryptoInput = JwtTokenUtility.Base64UrlEncode(
                mac.ComputeHash(Encoding.UTF8.GetBytes(jwt.GetSigningInput()))
                );

            if (!string.Equals(jwt.Signature, cryptoInput, StringComparison.Ordinal))
                throw new SignatureVerificationFailedException("Token contents do not match signature.");

            var utcNow = DateTime.UtcNow;

            if (utcNow + Configuration.MaxClockSkew < token.ValidFrom)
                throw new SecurityTokenNotYetValidException();

            if (utcNow + Configuration.MaxClockSkew > token.ValidTo)
                throw new SecurityTokenExpiredException();
            
            // TODO: Audience uri bearer token check.
            if (Configuration.AudienceRestriction.AudienceMode != AudienceUriMode.Never)
            {
                if (string.IsNullOrWhiteSpace(jwt.ClaimsSection.Audience))
                    throw new AudienceUriValidationFailedException("Token does not contain Audience uri.");

                var uri = new Uri(jwt.ClaimsSection.Audience);
                
                if (!Configuration.AudienceRestriction.AllowedAudienceUris.Contains(uri))
                {
                    throw new AudienceUriValidationFailedException(
                        string.Format("Uri {0} is not spceified in audience uri section", uri.ToString())
                        );
                }
            }

            if (Configuration.DetectReplayedTokens)
                DetectReplayedTokens(token);

            var inputIdentity = new ClaimsIdentity(jwt.ClaimsSection.Claims);

            if (Configuration.SaveBootstrapTokens)
                inputIdentity.BootstrapToken = token;

            return new ClaimsIdentityCollection(new [] {inputIdentity});
        }

        public override void WriteToken(XmlWriter writer, SecurityToken token)
        {
            if (token == null)
                throw new ArgumentNullException("token");

            var wrappedElement = 
                JwtTokenUtility.WrapInsideBinarySecurityToken(((JsonWebToken)token).GetRawToken());
            wrappedElement.WriteTo(writer);
        }

        public override SecurityToken CreateToken(SecurityTokenDescriptor tokenDescriptor)
        {
            if (tokenDescriptor == null)
                throw new ArgumentNullException("tokenDescriptor");

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

        public override SecurityKeyIdentifierClause CreateSecurityTokenReference(SecurityToken token, bool attached)
        {
            var jwt = token as JsonWebToken;
            if (jwt == null)
                throw new InvalidOperationException("JsonWebToken expected.");

            return new KeyNameIdentifierClause(jwt.ClaimsSection.Issuer);
        }
    }
}