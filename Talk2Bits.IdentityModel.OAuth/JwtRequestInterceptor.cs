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
    /// <summary>
    /// Performs security token validation and establishes security context.
    /// </summary>
    public class JwtRequestInterceptor : RequestInterceptor
    {
        private const string AccessTokenPrefix = "JWT ";

        private FederatedServiceCredentials _wifCredentials;

        public JwtRequestInterceptor(ServiceCredentials credentials) : base(true)
        {
            if (credentials == null)
                throw new ArgumentNullException("credentials");

            _wifCredentials = credentials as FederatedServiceCredentials;

            if (_wifCredentials == null)
                throw new InvalidOperationException("WIF is not configured.");                        
        }

        /// <summary>
        /// Processes the request.
        /// </summary>
        /// <param name="requestContext">The request context.</param>
        public override void ProcessRequest(ref RequestContext requestContext)
        {
            // This is place where all WIF magic happens. For normal SOAP services
            // WIF pipeline will handle all this stuff behind the scenes. For
            // RESTful services we have to intercept request before it reaches
            // WIF pipeline and perform all requiered actions ourself.

            try
            {
                var httpRequest =
                    requestContext.RequestMessage.Properties[HttpRequestMessageProperty.Name] as HttpRequestMessageProperty;
                if (httpRequest == null)
                    throw new WebFaultException(HttpStatusCode.BadRequest);

                string accessToken = null;

                try
                {
                    // Extracting raw token from Authorization HTTP header.
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

                // Wrapping parsed JWT inside XML envelope so WIF would be able to handle it.
                var wrappedToken = JwtTokenUtility.WrapInsideBinarySecurityToken(accessToken);

                using (var reader = wrappedToken.CreateReader())
                {
                    // Code bellow performs same actions as WIF pipeline does.

                    // Defining list of token handlers that can be used to validate incoming token.
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
                    
                    // Creating authorization context. This code will set Thread.CurrentPrincipal
                    // to ClaimsPrincipal defined by security token.
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

            var auth = authorizationHeader.Trim();

            if (!auth.StartsWith(AccessTokenPrefix))
                return null;

            return authorizationHeader.Remove(0, AccessTokenPrefix.Length).Trim();
        }
    }
}