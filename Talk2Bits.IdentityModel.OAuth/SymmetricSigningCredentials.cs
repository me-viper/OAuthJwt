using System;
using System.IdentityModel.Tokens;

namespace Talk2Bits.IdentityModel.OAuth
{
    /// <summary>
    /// Represents the cryptographic key and security algorithms that are used to generate a digital signature.
    /// </summary>
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