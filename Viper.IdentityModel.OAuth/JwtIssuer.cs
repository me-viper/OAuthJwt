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

namespace Viper.IdentityModel.OAuth
{
    internal class JwtIssuer : IJwtIssuerContract
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
                var rst = new RequestSecurityToken(JwtSecurityTokenHandler.TokenTypeIdentifier)
                    {
                        RequestType = WSTrust13Constants.RequestTypes.Issue,
                        AppliesTo = ContainsKey(parameters, "wrap_scope")
                            ? new EndpointAddress(parameters["wrap_scope"])
                            : null
                    };
                var securityTokenService = wifConfiguration.CreateSecurityTokenService();
                var rstr = securityTokenService.Issue(new ClaimsPrincipal(identities), rst);
                var jwt = (JsonWebToken)rstr.RequestedSecurityToken.SecurityToken;
                response = "wrap_access_token" + jwt.GetRawToken();
            }
            catch (Exception)
            {
                throw new WebFaultException<string>("Failed to issue security token.", HttpStatusCode.BadRequest);
            }

            return new MemoryStream(Encoding.ASCII.GetBytes(response));
        }

        private static SecurityToken GetTokenHandler(NameValueCollection parameters)
        {
            if (ContainsKey(parameters, "wrap_name") && ContainsKey(parameters, "wrap_password"))
                return new UserNameSecurityToken(parameters["wrap_name"], parameters["wrap_password"]);

            // TODO: Support other token handlers.
            throw new NotSupportedException("Unsupported token type.");
        }
        
        private static bool ContainsKey(NameObjectCollectionBase collection, string key)
        {
            return collection.Keys.Cast<string>().Any(ckey => ckey.Equals(key, StringComparison.Ordinal));
        }
    }
}