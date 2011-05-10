﻿using System;
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

            public override RequestSecurityTokenResponse Issue(IClaimsPrincipal principal, RequestSecurityToken request)
            {
                // - Just to enable break points. Should be removed later.
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
