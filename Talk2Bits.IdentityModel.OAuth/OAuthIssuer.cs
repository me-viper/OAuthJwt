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
    /// <summary>
    /// Base class for IP that use OAuth authorization protocol to issue security tokens.
    /// </summary>
    internal abstract class OAuthIssuer
    {
        /// <summary>
        /// Type of token that should be issued by IP.
        /// </summary>
        protected abstract string TokenTypeIdentifier { get; }

        /// <summary>
        /// Issues security token.
        /// </summary>
        /// <param name="request">
        /// The request containing all information required to issue security token
        /// according to OAuth v2 specification.
        /// </param>
        /// <returns>Issued token.</returns>
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

        /// <summary>
        /// 
        /// </summary>
        /// <param name="parameters">Security token request parameters.</param>
        /// <param name="grantType">
        /// OAuth grant type that specifies how client credentials should be
        /// validated.
        /// </param>
        /// <returns>Security token.</returns>
        protected virtual SecurityToken GetSecurityToken(NameValueCollection parameters, string grantType)
        {
            if (string.Equals(grantType, OAuthGrantTypes.Password, StringComparison.OrdinalIgnoreCase))
            {
                var userName = GetParameterOrThrow(parameters, OAuthParameters.UserName);
                var password = GetParameterOrThrow(parameters, OAuthParameters.Password);
                
                return new UserNameSecurityToken(userName, password);
            }

            // TODO: Support other grant types.
            throw new OAuthWebException(OAuthError.UnsupportedGrantType);
        }

        /// <summary>
        /// Extracts parameter with specified key from request.
        /// </summary>
        /// <param name="parameters">Security token request paramters.</param>
        /// <param name="parameter">Key of paramenter that should be extracted.</param>
        /// <returns>Parameter value.</returns>
        /// <exception cref="OAuthWebException">
        /// Security token request does not contain parameter with specified key.
        /// </exception>
        protected static string GetParameterOrThrow(NameValueCollection parameters, string parameter)
        {
            if (!ContainsKey(parameters, parameter))
                throw new OAuthWebException(OAuthError.InvalidRequest, string.Format("{0} is not specified.", parameter));

            return parameters[parameter];
        }

        /// <summary>
        /// Determines whether security token request contains parameter with specified key.
        /// </summary>
        /// <param name="collection">Security token request parameters.</param>
        /// <param name="key">Parameter key.</param>
        /// <returns>
        /// 	<c>true</c> if security token request contains parameter with key; otherwise, <c>false</c>.
        /// </returns>
        protected static bool ContainsKey(NameObjectCollectionBase collection, string key)
        {
            return collection.Keys.Cast<string>().Any(ckey => ckey.Equals(key, StringComparison.Ordinal));
        }

        /// <summary>
        /// Issues security token.
        /// </summary>
        /// <param name="requestParameters">
        /// The request containing all information required to issue security token
        /// according to OAuth v2 specification.
        /// </param>
        /// <returns>Issued token.</returns>
        private Stream Issue(string requestParameters)
        {
            // That is not real issuer. Big idea here is to accept
            // REST token request (OAuth has nothing in common with WSTrust)
            // perform necessary validations/transformations, call real
            // issuer and than make transformations again to form response.

            var parameters = HttpUtility.ParseQueryString(requestParameters);
            var grantType = GetParameterOrThrow(parameters, OAuthParameters.GrantType);

            // Creating security token depending on grant type.
            var securityToken = GetSecurityToken(parameters, grantType);

            var wifConfiguration = ((OAuthIssuerServiceHost)OperationContext.Current.Host).Configuration;
            ClaimsIdentityCollection identities = null;

            try
            {
                // WIF would do this automatically but in RESTful case we are on our own.
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

            // Making things look like client called real issuer directly.
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

            // Transforming issued token back to form that is expected by client.
            var token = GetResponse(rstr.RequestedSecurityToken.SecurityToken);
            if (token == null || !token.Validate())
                throw new OAuthWebException(HttpStatusCode.InternalServerError);

            var tokenString = JsonConvert.SerializeObject(token);
            
            return new MemoryStream(Encoding.ASCII.GetBytes(tokenString));
        }
    }
}