using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;

using Microsoft.IdentityModel.Claims;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace Talk2Bits.IdentityModel.OAuth
{
    /// <summary>
    /// Serializes and deserializes instance of type <see cref="Collection{Claim}"/> into JSON format.
    /// </summary>
    /// <remarks>
    /// <see cref="Claim"/> is not easy class to work with (in terms of serialization).
    /// Though this might be annoying we still need to handle all (de)serialization logic ourself.
    /// </remarks>
    public class JsonClaimsConverterCollection : JsonConverter
    {
        /// <summary>
        /// Writes the JSON representation of the object.
        /// </summary>
        /// <param name="writer">The <see cref="T:Newtonsoft.Json.JsonWriter"/> to write to.</param>
        /// <param name="value">The value.</param>
        /// <param name="serializer">The calling serializer.</param>
        public override void WriteJson(JsonWriter writer, object value, JsonSerializer serializer)
        {
            var claims = (IEnumerable<Claim>)value;

            writer.WriteStartObject();
            writer.WritePropertyName("http://schemas.bradycorp.com/2010/03/jwt/claims");
            
            writer.WriteStartArray();

            //! Not all properties of Claim are serialized.
            foreach (var claim in claims)
            {
                writer.WriteStartObject();
                writer.WritePropertyName("ClaimType");
                writer.WriteValue(claim.ClaimType);
                writer.WritePropertyName("Value");
                writer.WriteValue(claim.Value);
                writer.WritePropertyName("ValueType");
                writer.WriteValue(claim.ValueType);
                writer.WritePropertyName("Issuer");
                writer.WriteValue(claim.Issuer);
                writer.WritePropertyName("OriginalIssuer");
                writer.WriteValue(claim.OriginalIssuer);
                writer.WritePropertyName("Properties");
                serializer.Serialize(writer, claim.Properties);
                writer.WriteEndObject();
            }

            writer.WriteEndArray();
            writer.WriteEndObject();
        }

        /// <summary>
        /// Reads the JSON representation of the object.
        /// </summary>
        /// <param name="reader">The <see cref="T:Newtonsoft.Json.JsonReader"/> to read from.</param>
        /// <param name="objectType">Type of the object.</param>
        /// <param name="existingValue">The existing value of object being read.</param>
        /// <param name="serializer">The calling serializer.</param>
        /// <returns>The object value.</returns>
        public override object ReadJson(JsonReader reader, Type objectType, object existingValue, JsonSerializer serializer)
        {
            var result = new Collection<Claim>();

            while (reader.Read())
            {
                if (reader.TokenType == JsonToken.EndArray)
                    break;

                if (reader.TokenType != JsonToken.StartObject)
                    continue;

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

            // Reading EndObject;
            reader.Read();

            return result;
        }

        public override bool CanConvert(Type objectType)
        {
            return typeof(ICollection<Claim>).IsAssignableFrom(objectType);
        }
    }
}