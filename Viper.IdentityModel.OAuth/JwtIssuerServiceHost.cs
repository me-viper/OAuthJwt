using System;

using Microsoft.ServiceModel.Web;

namespace Viper.IdentityModel.OAuth
{
    public class JwtIssuerServiceHost : WebServiceHost2
    {
        public JwtIssuerServiceHost(JwtIssuerConfiguration configuration)
            : this(typeof(JwtIssuerServiceHost), null, configuration)
        {
        }

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