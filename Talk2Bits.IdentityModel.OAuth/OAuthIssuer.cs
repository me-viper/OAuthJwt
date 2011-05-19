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
    internal abstract class OAuthIssuer
    {
        protected abstract string TokenTypeIdentifier { get; }

        public Stream Issue(Stream request)
        {
            WebOperationContext.Current.OutgoingResponse.ContentType = "application/json; charset=utf-8";
            WebOperationContext.Current.OutgoingResponse.Headers[HttpResponseHeader.CacheControl] = "no-store";

            if (request == null)
                throw new OAuthWebException(OAuthError.InvalidRequest);

            string postData = null;

            var sr = new StreamReader(request);
            postData = sr.ReadToEnd();

            if (string.IsNullOrWhiteSpace(postData))
                throw new OAuthWebException(OAuthError.InvalidRequest);

            return Issue(postData);
        }
        
        protected abstract void WriteToken(Stream response, SecurityToken token);

        protected virtual SecurityToken GetTokenHandler(NameValueCollection parameters)
        {
            var grantType = GetParameterOrThrow(parameters, OAuthParameters.GrantType);

            if (string.Equals(grantType, OAuthGrantTypes.Password, StringComparison.OrdinalIgnoreCase))
            {
                var userName = GetParameterOrThrow(parameters, OAuthParameters.UserName);
                var password = GetParameterOrThrow(parameters, OAuthParameters.Password);
                
                return new UserNameSecurityToken(userName, password);
            }

            // TODO: Support other token handlers.
            throw new OAuthWebException(OAuthError.UnsupportedGrantType);
        }

        private static string GetParameterOrThrow(NameValueCollection parameters, string parameter)
        {
            if (!ContainsKey(parameters, parameter))
                throw new OAuthWebException(OAuthError.InvalidRequest, string.Format("{0} is not specified.", parameter));

            return parameters[parameter];
        }

        private static bool ContainsKey(NameObjectCollectionBase collection, string key)
        {
            return collection.Keys.Cast<string>().Any(ckey => ckey.Equals(key, StringComparison.Ordinal));
        }

        private Stream Issue(string requestParameters)
        {
            var parameters = HttpUtility.ParseQueryString(requestParameters);
            var tokenHandler = GetTokenHandler(parameters);

            if (!ContainsKey(parameters, OAuthParameters.Scope))
                throw new OAuthWebException(OAuthError.InvalidRequest);

            var wifConfiguration = ((OAuthIssuerServiceHost)OperationContext.Current.Host).Configuration;

            ClaimsIdentityCollection identities = null;

            try
            {
                identities = wifConfiguration.SecurityTokenHandlers.ValidateToken(tokenHandler);
            }
            catch (Exception)
            {
                throw new OAuthWebException(OAuthError.InvalidGrant);
            }

            var response = new MemoryStream();

            try
            {
                var rst = new RequestSecurityToken(RequestTypes.Issue)
                {
                    TokenType = TokenTypeIdentifier,
                    AppliesTo = ContainsKey(parameters, OAuthParameters.Scope)
                        ? new EndpointAddress(parameters[OAuthParameters.Scope])
                        : null
                };
                var securityTokenService = wifConfiguration.CreateSecurityTokenService();
                var rstr = securityTokenService.Issue(new ClaimsPrincipal(identities), rst);

                WriteToken(response, rstr.RequestedSecurityToken.SecurityToken);
                response.Seek(0, SeekOrigin.Begin);
            }
            catch (InvalidRequestException)
            {
                throw new OAuthWebException(OAuthError.InvalidScope);
            }
            catch (Exception)
            {
                throw new OAuthWebException(OAuthError.InvalidClient, "Failed to issue security token");
            }

            return response;
        }
    }
}