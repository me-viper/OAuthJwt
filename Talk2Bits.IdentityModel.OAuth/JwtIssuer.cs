using System;
using System.Collections.Specialized;
using System.IdentityModel.Tokens;
using System.IO;
using System.Linq;
using System.Net;
using System.ServiceModel;
using System.ServiceModel.Web;
using System.Text;
using System.Web;

using Microsoft.IdentityModel.Claims;
using Microsoft.IdentityModel.Protocols.WSTrust;
using Microsoft.IdentityModel.SecurityTokenService;

namespace Talk2Bits.IdentityModel.OAuth
{
    internal class JwtIssuer : IOAuthIssuerContract
    {
        public Stream Issue(Stream request)
        {
            if (request == null)
                throw new WebFaultException(HttpStatusCode.BadRequest);

            string postData = null;

            using (var sr = new StreamReader(request))
            {
                postData = sr.ReadToEnd();
            }

            if (string.IsNullOrWhiteSpace(postData))
                throw new WebFaultException(HttpStatusCode.BadRequest);

            var parameters = HttpUtility.ParseQueryString(postData);
            var tokenHandler = GetTokenHandler(parameters);

            if (!ContainsKey(parameters, OAuthParameters.Scope))
                throw new WebFaultException(HttpStatusCode.BadRequest);

            var wifConfiguration = ((JwtIssuerServiceHost)OperationContext.Current.Host).Configuration;
            
            ClaimsIdentityCollection identities = null;

            try
            {
                identities = wifConfiguration.SecurityTokenHandlers.ValidateToken(tokenHandler);
            }
            catch (Exception)
            {
                throw new WebFaultException<string>("Token validation failed.", HttpStatusCode.Forbidden);
            }

            string response = null;

            try
            {
                var rst = new RequestSecurityToken(RequestTypes.Issue)
                    {
                        TokenType = JwtSecurityTokenHandler.TokenTypeIdentifier,
                        AppliesTo = ContainsKey(parameters, OAuthParameters.Scope)
                            ? new EndpointAddress(parameters[OAuthParameters.Scope])
                            : null
                    };
                var securityTokenService = wifConfiguration.CreateSecurityTokenService();
                var rstr = securityTokenService.Issue(new ClaimsPrincipal(identities), rst);
                var jwt = (JsonWebToken)rstr.RequestedSecurityToken.SecurityToken;
                
                response = string.Format("{{\"access_token\":\"{0}\",\"token_type\":\"jwt\"}}", jwt.GetRawToken());
            }
            catch (Exception)
            {
                throw new WebFaultException<string>("Failed to issue security token.", HttpStatusCode.BadRequest);
            }

            return new MemoryStream(Encoding.ASCII.GetBytes(response));
        }

        private static SecurityToken GetTokenHandler(NameValueCollection parameters)
        {
            if (ContainsKey(parameters, OAuthParameters.UserName) && ContainsKey(parameters, OAuthParameters.Password))
                return new UserNameSecurityToken(parameters[OAuthParameters.UserName], parameters[OAuthParameters.Password]);

            // TODO: Support other token handlers.
            throw new NotSupportedException("Unsupported token type.");
        }
        
        private static bool ContainsKey(NameObjectCollectionBase collection, string key)
        {
            return collection.Keys.Cast<string>().Any(ckey => ckey.Equals(key, StringComparison.Ordinal));
        }
    }
}