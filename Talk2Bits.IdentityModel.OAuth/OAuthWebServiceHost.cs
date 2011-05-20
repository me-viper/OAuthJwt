using System;
using System.ServiceModel.Description;

using Microsoft.IdentityModel.Tokens;
using Microsoft.ServiceModel.Web;

namespace Talk2Bits.IdentityModel.OAuth
{
    /// <summary>
    /// Host for services that use OAuth in Federated Security environment.
    /// </summary>
    public class OAuthWebServiceHost : WebServiceHost2
    {
        public OAuthWebServiceHost(Type serviceType, params Uri[] baseAddresses) 
            : base(serviceType, false, baseAddresses)
        {
            PrincipalPermissionMode = PrincipalPermissionMode.Custom;
            FederatedServiceCredentials.ConfigureServiceHost(this);
            Interceptors.Add(new JwtRequestInterceptor(Credentials));
        }

    }
}