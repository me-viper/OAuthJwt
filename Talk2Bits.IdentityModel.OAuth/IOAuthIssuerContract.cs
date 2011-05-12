using System.IO;
using System.ServiceModel;
using System.ServiceModel.Web;

namespace Talk2Bits.IdentityModel.OAuth
{
    [ServiceContract]
    public interface IOAuthIssuerContract
    {
        [WebInvoke(UriTemplate = "")]
        Stream Issue(Stream request);
    }
}