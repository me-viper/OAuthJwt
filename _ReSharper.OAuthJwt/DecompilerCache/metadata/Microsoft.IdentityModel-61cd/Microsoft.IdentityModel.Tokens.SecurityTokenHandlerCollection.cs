// Type: Microsoft.IdentityModel.Tokens.SecurityTokenHandlerCollection
// Assembly: Microsoft.IdentityModel, Version=3.5.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35
// Assembly location: C:\Program Files\Reference Assemblies\Microsoft\Windows Identity Foundation\v3.5\Microsoft.IdentityModel.dll

using Microsoft.IdentityModel.Claims;

using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IdentityModel.Tokens;
using System.Xml;

namespace Microsoft.IdentityModel.Tokens
{
    public class SecurityTokenHandlerCollection : Collection<SecurityTokenHandler>
    {
        public SecurityTokenHandlerCollection();
        public SecurityTokenHandlerCollection(SecurityTokenHandlerConfiguration configuration);
        public SecurityTokenHandlerCollection(IEnumerable<SecurityTokenHandler> handlers);

        public SecurityTokenHandlerCollection(
            IEnumerable<SecurityTokenHandler> handlers, SecurityTokenHandlerConfiguration configuration);

        public SecurityTokenHandler this[string tokenTypeIdentifier] { get; }
        public SecurityTokenHandler this[SecurityToken token] { get; }
        public SecurityTokenHandler this[Type tokenType] { get; }
        public SecurityTokenHandlerConfiguration Configuration { get; }
        public IEnumerable<Type> TokenTypes { get; }
        public IEnumerable<string> TokenTypeIdentifiers { get; }

        public static SecurityTokenHandlerCollection CreateDefaultSecurityTokenHandlerCollection();

        public static SecurityTokenHandlerCollection CreateDefaultSecurityTokenHandlerCollection(
            SecurityTokenHandlerConfiguration configuration);

        public void AddOrReplace(SecurityTokenHandler handler);
        protected override void ClearItems();
        protected override void InsertItem(int index, SecurityTokenHandler item);
        protected override void RemoveItem(int index);
        protected override void SetItem(int index, SecurityTokenHandler item);
        public bool CanReadToken(XmlReader reader);
        public bool CanWriteToken(SecurityToken token);
        public SecurityToken CreateToken(SecurityTokenDescriptor tokenDescriptor);
        public ClaimsIdentityCollection ValidateToken(SecurityToken token);
        public SecurityToken ReadToken(XmlReader reader);
        public void WriteToken(XmlWriter writer, SecurityToken token);
    }
}
