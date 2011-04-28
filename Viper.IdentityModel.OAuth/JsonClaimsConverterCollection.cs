using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using Microsoft.IdentityModel.Claims;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace Viper.IdentityModel.OAuth
{
    public class JsonClaimsConverterCollection : JsonConverter
    {
        public override void WriteJson(JsonWriter writer, object value, JsonSerializer serializer)
        {
            serializer.Serialize(writer, value);
        }

        public override object ReadJson(JsonReader reader, Type objectType, object existingValue, JsonSerializer serializer)
        {
            var result = new Collection<Claim>();

            while (reader.Read())
            {
                if (reader.TokenType != JsonToken.StartObject)
                    break;

                var jo = JObject.Load(reader);
                var claim = new Claim(
                    (string)jo["ClaimType"],
                    (string)jo["Value"],
                    (string)jo["ValueType"],
                    (string)jo["Issuer"],
                    (string)jo["OriginalIssuer"]
                    );
                var jt = jo["Properties"];
                var props = serializer.Deserialize<Dictionary<string, string>>(jt.CreateReader());
                
                foreach (var entry in props)
                    claim.Properties.Add(entry.Key, entry.Value);
                
                result.Add(claim);
            }

            return result;
        }

        public override bool CanConvert(Type objectType)
        {
            return typeof(ICollection<Claim>).IsAssignableFrom(objectType);
        }
    }
}