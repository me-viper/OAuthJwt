using System;
using System.IdentityModel.Tokens;
using System.ServiceModel;
using System.ServiceModel.Description;
using System.ServiceModel.Web;
using System.Threading;

using Microsoft.IdentityModel.Claims;
using Microsoft.IdentityModel.Tokens;
using Microsoft.ServiceModel.Web;

using Talk2Bits.IdentityModel.OAuth;

namespace TestService
{
    [ServiceContract]
    public class TestService
    {
        [WebGet]
        public string Hello()
        {
            Console.WriteLine("Hello called...");
            Console.WriteLine("------------------");
            var cp = Thread.CurrentPrincipal as IClaimsPrincipal;
            if (cp != null)
            {
                foreach (var id in cp.Identities)
                {
                    Console.WriteLine("Authentication Type: " + id.AuthenticationType);
                    Console.WriteLine("Is Authenticated: " + id.IsAuthenticated);
                    Console.WriteLine("Name: " + id.Name);
                    Console.WriteLine();
                    Console.WriteLine("Claims...");

                    foreach (var c in id.Claims)
                    {
                        Console.WriteLine(c.ClaimType + ": " + c.Value);
                    }
                }
            }
            return "Hello, World";
        }
    }

    public class Program
    {
        public static void Main(string[] args)
        {
            var host = new WebServiceHost2(typeof(TestService), false, new Uri("http://localhost:9090"));
            host.PrincipalPermissionMode = PrincipalPermissionMode.Custom;
            FederatedServiceCredentials.ConfigureServiceHost(host);
            host.Interceptors.Add(new JwtRequestInterceptor(host.Credentials));            
            host.Open();

            foreach (var ep in host.Description.Endpoints)
            {
                Console.WriteLine(ep.ListenUri);
            }

            Console.WriteLine("Ready...");
            Console.ReadLine();
            host.Close();
        }
    }

    public class SimpleRegistry : IssuerNameRegistry
    {
        public override string GetIssuerName(SecurityToken securityToken)
        {
            var jwt = securityToken as JsonWebToken;
            if (jwt == null)
                throw new InvalidOperationException("JsonWebToken is expected.");

            // All issuers are trusted.
            return jwt.ClaimsSection.Issuer;
        }
    }
}
