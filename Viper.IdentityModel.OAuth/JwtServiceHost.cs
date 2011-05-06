using System;
using System.ServiceModel.Web;

namespace Viper.IdentityModel.OAuth
{
    public class JwtServiceHost : WebServiceHost
    {
        public JwtServiceHost(JwtServiceConfiguration configuration)
            : this(typeof(JwtServiceHost), null, configuration)
        {
        }

        public JwtServiceHost(
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