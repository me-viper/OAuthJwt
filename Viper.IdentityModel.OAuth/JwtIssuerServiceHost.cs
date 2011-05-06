using System;
using System.ServiceModel.Web;

namespace Viper.IdentityModel.OAuth
{
    public class JwtIssuerServiceHost : WebServiceHost
    {
        public JwtIssuerServiceHost(JwtServiceConfiguration configuration)
            : this(typeof(JwtIssuerServiceHost), null, configuration)
        {
        }

        public JwtIssuerServiceHost(
            Type serviceType, 
            Uri[] baseAddresses, 
            JwtServiceConfiguration configuration) : base(serviceType, baseAddresses)
        {
            if (configuration == null)
                throw new ArgumentNullException("configuration");

            Configuration = configuration;
        }

        public JwtServiceConfiguration Configuration { get; private set; }
    }
}