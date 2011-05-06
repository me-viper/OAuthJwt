using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Text;
using System.Xml;

using Microsoft.IdentityModel.Claims;
using Microsoft.IdentityModel.Configuration;
using Microsoft.IdentityModel.Protocols.WSTrust;
using Microsoft.IdentityModel.SecurityTokenService;
using Microsoft.IdentityModel.Tokens;

using Viper.IdentityModel.OAuth;

namespace TestIssuer
{
    public class UserNamePasswordSecurityTokenHandler : UserNameSecurityTokenHandler
    {
        public override bool CanReadToken(XmlReader reader)
        {
            return true;
        }

        public override ClaimsIdentityCollection ValidateToken(SecurityToken token)
        {
            
        }
    }

    public class Program
    {
        public static void Main(string[] args)
        {
            var config = new JwtIssuerConfiguration { SecurityTokenService = typeof(JwtSecurityTokenService) };
            config.TokenIssuerName = "MyCustomIssuer";

            config.SecurityTokenHandlers.AddOrReplace();

            var wsh = new OAuthServiceHost(config, new Uri("http://localhost:9111/WRAPv0.9"));
            wsh.Open();

            foreach (var ep in wsh.Description.Endpoints)
            {
                Console.WriteLine(ep.ListenUri);
            }
            Console.WriteLine("OAuth Issuer Ready...");
            Console.ReadLine();

            wsh.Close();
        }

        public class JwtSecurityTokenService : SecurityTokenService
        {
            public JwtSecurityTokenService(SecurityTokenServiceConfiguration securityTokenServiceConfiguration) 
                : base(securityTokenServiceConfiguration)
            {
            }

            protected override Scope GetScope(
                IClaimsPrincipal principal, 
                RequestSecurityToken request)
            {
                var scope = new Scope { AppliesToAddress = request.AppliesTo.Uri.AbsoluteUri };

                scope.TokenEncryptionRequired = false;
                scope.SymmetricKeyEncryptionRequired = false;
                scope.SigningCredentials = new SymmetricSigningCredentials("Sapm9PPZZHly7a9319mksllija112suapoqc321jvso=");
                return scope;
            }

            public override RequestSecurityTokenResponse Issue(IClaimsPrincipal principal, RequestSecurityToken request)
            {
                return base.Issue(principal, request);
            }

            protected override IClaimsIdentity GetOutputClaimsIdentity(
                IClaimsPrincipal principal, 
                RequestSecurityToken request, 
                Scope scope)
            {
                return new ClaimsIdentity(
                    new []
                        {
                            new Claim(ClaimTypes.Name, "Test"),
                            new Claim("Role", "Administrator")
                        }
                    );
            }
        }
    }
}
