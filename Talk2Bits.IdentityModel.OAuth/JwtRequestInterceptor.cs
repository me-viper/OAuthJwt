using System;
using System.Collections.Generic;
using System.IdentityModel.Policy;
using System.Net;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.ServiceModel.Description;
using System.ServiceModel.Security;
using System.ServiceModel.Web;

using Microsoft.IdentityModel.Claims;
using Microsoft.IdentityModel.Tokens;
using Microsoft.ServiceModel.Web;

namespace Talk2Bits.IdentityModel.OAuth
{
    public class JwtRequestInterceptor : RequestInterceptor
    {
        private const string AccessTokenPrefix = "wrap_access_token";

        private FederatedServiceCredentials _wifCredentials;

        public JwtRequestInterceptor(ServiceCredentials credentials) : base(true)
        {
            if (credentials == null)
                throw new ArgumentNullException("credentials");

            _wifCredentials = credentials as FederatedServiceCredentials;

            if (_wifCredentials == null)
                throw new InvalidOperationException("WIF is not configured.");                        
        }

        public override void ProcessRequest(ref RequestContext requestContext)
        {
            try
            {
                var httpRequest =
                    requestContext.RequestMessage.Properties[HttpRequestMessageProperty.Name] as HttpRequestMessageProperty;
                if (httpRequest == null)
                    throw new WebFaultException(HttpStatusCode.BadRequest);

                string accessToken = null;

                try
                {
                    accessToken = ExtractToken(httpRequest.Headers[HttpRequestHeader.Authorization]);                
                    if (string.IsNullOrWhiteSpace(accessToken))
                        throw new WebFaultException(HttpStatusCode.Unauthorized);
                }
                catch (WebFaultException)
                {
                    throw;
                }
                catch (Exception)
                {
                    throw new WebFaultException(HttpStatusCode.BadRequest);
                }

                var wrappedToken = JwtTokenUtility.WrapInsideBinarySecurityToken(accessToken);

                using (var reader = wrappedToken.CreateReader())
                {
                    var handlersCollection =
                        _wifCredentials.SecurityTokenHandlerCollectionManager[SecurityTokenHandlerCollectionManager.Usage.Default];
                    
                    if (!handlersCollection.CanReadToken(reader))
                        throw new InvalidOperationException("Security token handler is not found.");

                    var token = handlersCollection.ReadToken(reader);
                    var identities = handlersCollection.ValidateToken(token);

                    var principal = _wifCredentials.ClaimsAuthenticationManager.Authenticate(
                        httpRequest.Method, 
                        new ClaimsPrincipal(identities)
                        );
                    var identityCollection = principal != null ? principal.Identities : new ClaimsIdentityCollection();
                    var authorizationContext =
                        new List<IAuthorizationPolicy> {new AuthorizationPolicy(identityCollection)}.AsReadOnly();

                    var security = SecurityMessageProperty.GetOrCreate(requestContext.RequestMessage);
                    security.ServiceSecurityContext = new ServiceSecurityContext(authorizationContext);
                }
            }
            catch (Exception)
            {
                throw new WebFaultException(HttpStatusCode.BadRequest);
            }
        }

        private static string ExtractToken(string authorizationHeader)
        {
            if (string.IsNullOrWhiteSpace(authorizationHeader))
                return null;

            var auth = authorizationHeader.Remove(0, AccessTokenPrefix.Length).TrimStart(' ');
            if (auth[0] != '=')
                return null;

            return auth.TrimStart('=', ' ').Trim('"');
        }
    }
}