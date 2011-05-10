using System;
using System.IdentityModel.Tokens;
using System.Xml;

using Microsoft.IdentityModel.Claims;
using Microsoft.IdentityModel.Tokens;

namespace TestIssuer
{
    public class UserNamePasswordSecurityTokenHandler : UserNameSecurityTokenHandler
    {
        public override bool CanValidateToken
        {
            get { return true; }
        }

        public override ClaimsIdentityCollection ValidateToken(SecurityToken token)
        {
            var userName = ((UserNameSecurityToken)token).UserName;
            IClaimsIdentity identity = new ClaimsIdentity(
                new[] { new Claim(ClaimTypes.Name, userName) },
                AuthenticationMethods.Password
                );

            if (Configuration.SaveBootstrapTokens)
                identity.BootstrapToken = RetainPassword ? token : new UserNameSecurityToken(userName, null);

            return new ClaimsIdentityCollection(new[] { identity });
        }
    }
}