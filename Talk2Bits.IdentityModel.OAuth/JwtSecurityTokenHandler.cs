using System;
using System.IdentityModel.Selectors;
using System.IdentityModel.Tokens;
using System.Security.Cryptography;
using System.ServiceModel.Security;
using System.Text;
using System.Xml;

using Microsoft.IdentityModel.Claims;
using Microsoft.IdentityModel.Protocols.XmlSignature;
using Microsoft.IdentityModel.Tokens;

namespace Talk2Bits.IdentityModel.OAuth
{
    /// <summary>
    /// Handles Json Security Tokens.
    /// </summary>
    public class JwtSecurityTokenHandler : SecurityTokenHandler
    {
        //! Not sure was namespace should be here. Specification does not (yet) define one.
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

        /// <summary>
        /// Determines whether this instance can parse specified raw security token.
        /// </summary>
        /// <param name="reader">The xml reader.</param>
        /// <returns>
        /// 	<c>true</c> if this instance can parse specified raw security token; otherwise, <c>false</c>.
        /// </returns>
        public override bool CanReadToken(XmlReader reader)
        {
            // See comments on WriteToken about this.
            return reader.IsStartElement("BinarySecurityToken", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd") &&
                reader.GetAttribute("ValueType") == "http://schemas.xmlsoap.org/ws/2009/11/jwt-token-profile-1.0";
        }

        /// <summary>
        /// Parses security token.
        /// </summary>
        /// <param name="reader">The xml reader.</param>
        /// <returns></returns>
        public override SecurityToken ReadToken(XmlReader reader)
        {
            if (!CanReadToken(reader))
                throw new InvalidOperationException("Invalid token.");

            reader.Read();
            var buffer = reader.ReadContentAsString();

            return JsonWebToken.ParseRawToken(buffer);
        }

        /// <summary>
        /// Validates security token.
        /// </summary>
        /// <param name="token">Security token.</param>
        /// <returns><see cref="ClaimsIdentityCollection"/> stored inside security token.</returns>
        public override ClaimsIdentityCollection ValidateToken(SecurityToken token)
        {
            if (token == null)
                throw new ArgumentNullException("token");

            var jwt = (JsonWebToken)token;

            // Stage 1: Validating token signature.
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

            // Signature is checked according to JSON Web Signature specification.
            var mac = new HMACSHA256(key.GetSymmetricKey());
            
            var cryptoInput = JwtTokenUtility.Base64UrlEncode(
                mac.ComputeHash(Encoding.UTF8.GetBytes(jwt.GetSigningInput()))
                );

            if (!string.Equals(jwt.Signature, cryptoInput, StringComparison.Ordinal))
                throw new SignatureVerificationFailedException("Token contents do not match signature.");

            // Stage 2: Checking whether token is up to date.
            var utcNow = DateTime.UtcNow;

            if (utcNow + Configuration.MaxClockSkew < token.ValidFrom)
                throw new SecurityTokenNotYetValidException();

            if (utcNow + Configuration.MaxClockSkew > token.ValidTo)
                throw new SecurityTokenExpiredException();
            
            // Stage 3: Checking whether we should even bother talking to specified RP.
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

            // Stage 4: If configured, let WIF check "Replay Token" attack.
            if (Configuration.DetectReplayedTokens)
                DetectReplayedTokens(token);

            // Stage 5: Extracting claims from security token.
            var inputIdentity = new ClaimsIdentity(jwt.ClaimsSection.Claims);

            // Stage 6: If configured, saving bootstrap token that may be
            // used by RP for delegation (ActAs and BehalfOf calls).
            if (Configuration.SaveBootstrapTokens)
                inputIdentity.BootstrapToken = token;

            return new ClaimsIdentityCollection(new [] {inputIdentity});
        }

        public override void WriteToken(XmlWriter writer, SecurityToken token)
        {
            if (token == null)
                throw new ArgumentNullException("token");

            // Json Web Token is presented in binary (to quite binary but whatever) format.
            // WIF does not care about it, WS-* stack works only with XML. Thus, just
            // wrapping our JWT with XML.
            var wrappedElement = 
                JwtTokenUtility.WrapInsideBinarySecurityToken(((JsonWebToken)token).GetRawToken());
            wrappedElement.WriteTo(writer);
        }

        /// <summary>
        /// Creates security token.
        /// </summary>
        /// <param name="tokenDescriptor">The token descriptor.</param>
        /// <returns>Security token.</returns>
        public override SecurityToken CreateToken(SecurityTokenDescriptor tokenDescriptor)
        {
            if (tokenDescriptor == null)
                throw new ArgumentNullException("tokenDescriptor");

            // See details in Json Web Token specification.
            var seconds = (tokenDescriptor.Lifetime.Expires - tokenDescriptor.Lifetime.Created) ?? new TimeSpan(0, 0, 3600);
            var header = new JwtHeaderSegment();
            var claims = new JwtClaimsSegment(
                tokenDescriptor.TokenIssuerName,
                tokenDescriptor.AppliesToAddress,
                DateTime.UtcNow,
                DateTime.UtcNow + seconds,
                tokenDescriptor.Subject.Claims
                );

            // See details in Json Web Signature specification.
            var key = (InMemorySymmetricSecurityKey)tokenDescriptor.SigningCredentials.SigningKey;
            var mac = new HMACSHA256(key.GetSymmetricKey());
            var hash = mac.ComputeHash(Encoding.UTF8.GetBytes(JsonWebToken.GetSigningInput(header, claims)));
            var jwsCryptoOutput = JwtTokenUtility.Base64UrlEncode(hash);

            return new JsonWebToken(header, claims, jwsCryptoOutput);
        }

        public override SecurityKeyIdentifierClause CreateSecurityTokenReference(SecurityToken token, bool attached)
        {
            //? WIF documentation is not clear about what this method does.
            //? The only thing I can say that this method is called on Issuer Token Resolution
            //? stage (IssuerTokenResolver). My idea that this function returns key
            //? that is used to resolve security keys.
            var jwt = token as JsonWebToken;
            if (jwt == null)
                throw new InvalidOperationException("JsonWebToken expected.");

            return new KeyNameIdentifierClause(jwt.ClaimsSection.Issuer);
        }
    }
}