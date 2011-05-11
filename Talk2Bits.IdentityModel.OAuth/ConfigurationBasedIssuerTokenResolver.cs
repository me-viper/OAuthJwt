using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.ServiceModel.Security;
using System.Xml;

using Microsoft.IdentityModel.Tokens;

namespace Talk2Bits.IdentityModel.OAuth
{
    public class ConfigurationBasedIssuerTokenResolver : IssuerTokenResolver
    {
        private IDictionary<string, SecurityKey> _keyMap = new Dictionary<string, SecurityKey>();

        public ConfigurationBasedIssuerTokenResolver(XmlNodeList customConfiguration)
        {
            if (customConfiguration == null)
                throw new ArgumentNullException("customConfiguration");

            if (customConfiguration.Count != 1)
                throw new InvalidOperationException("Invalid configuration.");

            var element = customConfiguration[0];

            if (!string.Equals(element.Name, "tokenResolvers", StringComparison.Ordinal))
                throw new InvalidOperationException("tokenResolvers expected.");

            foreach (XmlNode node in element.ChildNodes)
            {
                if (node.Name.Equals("add", StringComparison.Ordinal))
                {
                    if (node.Attributes == null || node.Attributes.Count == 0)
                        throw new InvalidOperationException(string.Format("Invalid {0} element", node.Name));

                    var nameNode = node.Attributes.GetNamedItem("name");
                    var signingKeyNode = node.Attributes.GetNamedItem("signingKey");

                    if (nameNode == null || string.IsNullOrWhiteSpace(nameNode.Value) ||
                        signingKeyNode == null || string.IsNullOrWhiteSpace(signingKeyNode.Value))
                    {
                        throw new InvalidOperationException(string.Format("Invalid {0} element", node.Name));
                    }

                    if (_keyMap.ContainsKey(nameNode.Value))
                        throw new InvalidOperationException(string.Format("Issuer '{0}' already has been added.", nameNode.Value));

                    _keyMap.Add(
                        nameNode.Value,
                        new InMemorySymmetricSecurityKey(Convert.FromBase64String(signingKeyNode.Value))
                        );

                    continue;
                }

                if (node.Name.Equals("remove", StringComparison.Ordinal))
                {
                    if (node.Attributes == null || node.Attributes.Count == 0)
                        throw new InvalidOperationException(string.Format("Invalid {0} element", node.Name));

                    var nameNode = node.Attributes.GetNamedItem("name");
                    var signingKeyNode = node.Attributes.GetNamedItem("signingKey");

                    if (nameNode == null || string.IsNullOrWhiteSpace(nameNode.Value) ||
                        signingKeyNode == null || string.IsNullOrWhiteSpace(signingKeyNode.Value))
                    {
                        throw new InvalidOperationException(string.Format("Invalid {0} element", node.Name));
                    }

                    if (_keyMap.ContainsKey(nameNode.Value))
                        _keyMap.Remove(nameNode.Value);

                    continue;
                }

                if (node.Name.Equals("clear", StringComparison.Ordinal))
                {
                    _keyMap.Clear();
                    continue;
                }

                throw new InvalidOperationException(string.Format("Node {0} is unxpected.", node.Name));
            }
        }

        protected override bool TryResolveSecurityKeyCore(SecurityKeyIdentifierClause keyIdentifierClause, out SecurityKey key)
        {
            key = null;
            var nameClause = keyIdentifierClause as KeyNameIdentifierClause;

            return nameClause != null && _keyMap.TryGetValue(nameClause.KeyName, out key);
        }
    }
}