using System.IO;
using System.ServiceModel;
using System.ServiceModel.Web;

namespace Viper.IdentityModel.OAuth
{
    [ServiceContract]
    public interface IJwtIssuerContract
    {
        [WebInvoke(UriTemplate = "")]
        Stream Issue(Stream request);
    }
}