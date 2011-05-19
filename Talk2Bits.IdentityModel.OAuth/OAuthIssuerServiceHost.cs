using System;
using System.ServiceModel.Web;

namespace Talk2Bits.IdentityModel.OAuth
{
    public class OAuthIssuerServiceHost : WebServiceHost
    {
        public OAuthIssuerServiceHost(OAuthIssuerConfiguration configuration)
            : this(typeof(JwtIssuer), null, configuration)
        {
        }

        public OAuthIssuerServiceHost(OAuthIssuerConfiguration configuration, Uri baseAddress)
            : this(typeof(JwtIssuer), new[] { baseAddress }, configuration)
        {}

        public OAuthIssuerServiceHost(
            Type serviceType, 
            Uri[] baseAddresses, 
            OAuthIssuerConfiguration configuration) : base(serviceType, baseAddresses)
        {
            if (configuration == null)
                throw new ArgumentNullException("configuration");

            Configuration = configuration;
        }

        public OAuthIssuerConfiguration Configuration { get; private set; }
    }
}