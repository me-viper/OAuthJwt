using System.Net;
using System.ServiceModel.Web;

namespace Talk2Bits.IdentityModel.OAuth
{
    /// <summary>
    /// Is thrown when authorization error occurs.
    /// </summary>
    public class OAuthWebException : WebFaultException<OAuthError>
    {
        public OAuthWebException(HttpStatusCode statusCode) : base(new OAuthError(statusCode), statusCode)
        {            
        }

        public OAuthWebException(string error) : this(new OAuthError(error))
        {            
        }

        public OAuthWebException(string error, string details) : this(new OAuthError(error, details))
        {
            
        }

        public OAuthWebException(string error, string details, string errorUri)
            : this(new OAuthError(error, details, errorUri))
        {
            
        }

        private OAuthWebException(OAuthError detail) : base(detail, HttpStatusCode.BadRequest)
        {
        }
    }
}