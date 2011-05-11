using System;
using System.Collections.Generic;
using System.Linq;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.ServiceModel.Web;
using System.Text;
using System.Threading;

using Microsoft.IdentityModel.Claims;
using Microsoft.ServiceModel.Web;

using Talk2Bits.IdentityModel.OAuth;

namespace TestService
{
    [ServiceContract]
    class TestService
    {
        [WebGet]
        string Hello()
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
            var host = new WebServiceHost2(typeof(TestService), new Uri("http://localhost:9090"));
            // ! How to get BindingContext? !
            //host.Interceptors.Add(new JwtRequestInterceptor());
            
            host.Open();

            foreach (var ep in host.Description.Endpoints)
            {
                var z = new CustomBinding(ep.Binding);
                
                Console.WriteLine(ep.ListenUri);
            }

            Console.WriteLine("Ready...");
            Console.ReadLine();
            host.Close();
        }
    }
}
