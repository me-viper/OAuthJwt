using System;
using System.Net;

using Newtonsoft.Json;

namespace Talk2Bits.IdentityModel.OAuth
{
    [JsonObject(MemberSerialization.OptIn)]
    public class OAuthError
    {
        /// <summary>
        /// The request is missing a required parameter, includes an
        /// unsupported parameter or parameter value, repeats a
        /// parameter, includes multiple credentials, utilizes more
        /// than one mechanism for authenticating the client, or is
        /// otherwise malformed.
        /// </summary>
        public const string InvalidRequest = "invalid_request";

        /// <summary>
        /// Client authentication failed (e.g. unknown client, no
        /// client credentials included, multiple client credentials
        /// included, or unsupported credentials type).  The
        /// authorization server MAY return an HTTP 401
        /// (Unauthorized) status code to indicate which HTTP
        /// authentication schemes are supported.  If the client
        /// attempted to authenticate via the "Authorization" request
        /// header field, the authorization server MUST respond with
        /// an HTTP 401 (Unauthorized) status code, and include the
        /// "WWW-Authenticate" response header field matching the
        /// authentication scheme used by the client.
        /// </summary>
        public const string InvalidClient = "invalid_client";

        /// <summary>
        /// The provided authorization grant is invalid, expired,
        /// revoked, does not match the redirection URI used in the
        /// authorization request, or was issued to another client.
        /// </summary>
        public const string InvalidGrant = "invalid_grant";

        /// <summary>
        /// The authenticated client is not authorized to use this
        /// authorization grant type.
        /// </summary>
        public const string UnauthorizedClient = "unauthorized_client";

        /// <summary>
        /// The authorization grant type is not supported by the
        /// authorization server.
        /// </summary>
        public const string UnsupportedGrantType = "unsupported_grant_type";

        /// <summary>
        /// The requested scope is invalid, unknown, malformed, or
        /// exceeds the scope granted by the resource owner.
        /// </summary>
        public const string InvalidScope = "invalid_scope";

        public OAuthError(HttpStatusCode statusCode) : this(statusCode.ToString())
        {            
        }

        public OAuthError(string error) : this(error, null)
        {
        }

        public OAuthError(string error, string description)
            : this(error, description, null)
        {
        }

        public OAuthError(string error, string description, string uri)
        {
            Error = string.IsNullOrWhiteSpace(error) ? InvalidRequest : error;
            Description = description;
            Uri = uri;
        }

        [JsonProperty("error")]
        public string Error { get; set; }

        [JsonProperty("error_description")]
        public string Description { get; set; }

        [JsonProperty("error_uri")]
        public string Uri { get; set; }
    }
}