using System;
using System.ServiceModel.Web;

namespace Talk2Bits.IdentityModel.OAuth
{
    public class JwtIssuerServiceHost : WebServiceHost
    {
        public JwtIssuerServiceHost(JwtIssuerConfiguration configuration)
            : this(typeof(JwtIssuer), null, configuration)
        {
        }

        public JwtIssuerServiceHost(JwtIssuerConfiguration configuration, Uri baseAddress)
            : this(typeof(JwtIssuer), new[] { baseAddress }, configuration)
        {}

        public JwtIssuerServiceHost(
            Type serviceType, 
            Uri[] baseAddresses, 
            JwtIssuerConfiguration configuration) : base(serviceType, baseAddresses)
        {
            if (configuration == null)
                throw new ArgumentNullException("configuration");

            Configuration = configuration;
        }

        public JwtIssuerConfiguration Configuration { get; private set; }
    }
}