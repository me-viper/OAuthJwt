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
using Microsoft.IdentityModel.Tokens;

using Newtonsoft.Json;

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

            Stream response = null;

            try
            {
                response = Issue(postData);
            }
            catch (Exception)
            {
                throw new OAuthWebException(HttpStatusCode.InternalServerError);
            }

            return response;
        }
        
        protected abstract OAuthTokenResponse GetResponse(SecurityToken token);

        protected virtual void PrepareRequestSecurityToken(RequestSecurityToken rst)
        {}

        protected virtual string GetTokenUsage()
        {
            return SecurityTokenHandlerCollectionManager.Usage.Default;
        }

        protected virtual SecurityToken GetSecurityToken(NameValueCollection parameters, string grantType)
        {
            if (string.Equals(grantType, OAuthGrantTypes.Password, StringComparison.OrdinalIgnoreCase))
            {
                var userName = GetParameterOrThrow(parameters, OAuthParameters.UserName);
                var password = GetParameterOrThrow(parameters, OAuthParameters.Password);
                
                return new UserNameSecurityToken(userName, password);
            }

            throw new OAuthWebException(OAuthError.UnsupportedGrantType);
        }

        protected static string GetParameterOrThrow(NameValueCollection parameters, string parameter)
        {
            if (!ContainsKey(parameters, parameter))
                throw new OAuthWebException(OAuthError.InvalidRequest, string.Format("{0} is not specified.", parameter));

            return parameters[parameter];
        }

        protected static bool ContainsKey(NameObjectCollectionBase collection, string key)
        {
            return collection.Keys.Cast<string>().Any(ckey => ckey.Equals(key, StringComparison.Ordinal));
        }

        private Stream Issue(string requestParameters)
        {
            var parameters = HttpUtility.ParseQueryString(requestParameters);
            var grantType = GetParameterOrThrow(parameters, OAuthParameters.GrantType);
            var securityToken = GetSecurityToken(parameters, grantType);

            var wifConfiguration = ((OAuthIssuerServiceHost)OperationContext.Current.Host).Configuration;
            ClaimsIdentityCollection identities = null;

            try
            {
                identities = wifConfiguration.SecurityTokenHandlerCollectionManager[GetTokenUsage()].ValidateToken(securityToken);
            }
            catch (AudienceUriValidationFailedException)
            {
                throw new OAuthWebException(OAuthError.InvalidScope);
            }
            catch (SecurityTokenValidationException)
            {
                throw new OAuthWebException(OAuthError.InvalidGrant);
            }
            catch (Exception)
            {
                throw new OAuthWebException(HttpStatusCode.InternalServerError);
            }

            RequestSecurityTokenResponse rstr = null;

            try
            {
                var rst = new RequestSecurityToken(RequestTypes.Issue)
                    {
                        TokenType = TokenTypeIdentifier,
                        AppliesTo = ContainsKey(parameters, OAuthParameters.Scope)
                            ? new EndpointAddress(parameters[OAuthParameters.Scope])
                            : null
                    };
                PrepareRequestSecurityToken(rst);
                var securityTokenService = wifConfiguration.CreateSecurityTokenService();
                rstr = securityTokenService.Issue(new ClaimsPrincipal(identities), rst);
            }
            catch (InvalidRequestException)
            {
                throw new OAuthWebException(OAuthError.InvalidScope);
            }
            catch (Exception)
            {
                throw new OAuthWebException(OAuthError.InvalidClient, "Failed to issue security token");
            }

            var token = GetResponse(rstr.RequestedSecurityToken.SecurityToken);
            if (token == null || !token.Validate())
                throw new OAuthWebException(HttpStatusCode.InternalServerError);

            var tokenString = JsonConvert.SerializeObject(token);
            
            return new MemoryStream(Encoding.ASCII.GetBytes(tokenString));
        }
    }
}