using System;

using Microsoft.IdentityModel.Claims;
using Microsoft.IdentityModel.Configuration;
using Microsoft.IdentityModel.Protocols.WSTrust;
using Microsoft.IdentityModel.SecurityTokenService;

using Talk2Bits.IdentityModel.OAuth;

namespace TestIssuer
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var config = new JwtIssuerConfiguration { SecurityTokenService = typeof(JwtSecurityTokenService) };
            config.TokenIssuerName = "MyCustomIssuer";

            config.SecurityTokenHandlers.AddOrReplace(new UserNamePasswordSecurityTokenHandler());

            var wsh = new JwtIssuerServiceHost(config, new Uri("http://localhost:9111/WRAPv0.9"));
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
