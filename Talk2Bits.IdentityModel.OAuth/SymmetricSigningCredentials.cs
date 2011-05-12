using System;
using System.IdentityModel.Tokens;

namespace Talk2Bits.IdentityModel.OAuth
{
    public class SymmetricSigningCredentials : SigningCredentials
    {
        public SymmetricSigningCredentials(string base64EncodedKey) 
            : this(Convert.FromBase64String(base64EncodedKey))
        {
        }

        public SymmetricSigningCredentials(byte[] key) : base(
            new InMemorySymmetricSecurityKey(key), 
            SecurityAlgorithms.HmacSha256Signature, 
            SecurityAlgorithms.Sha256Digest)
        {
        }
    }
}