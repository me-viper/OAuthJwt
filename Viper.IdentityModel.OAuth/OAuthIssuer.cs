using System;
using System.IO;
using System.Net;
using System.ServiceModel.Web;

namespace Viper.IdentityModel.OAuth
{
    public class OAuthIssuer : IOAuthIssuerContract
    {
        public Stream Issue(Stream request)
        {
            if (request == null)
                throw new WebFaultException(HttpStatusCode.BadRequest);
        }
    }
}