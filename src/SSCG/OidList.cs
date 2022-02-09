using System.Security.Cryptography;

namespace SSCG
{
    public static class OidList
    {
        /// <summary>
        /// SSL Oid Collection
        /// </summary>
        /// <returns>Server Authentication and Client Authentication</returns>
        public static OidCollection SSL()
        {
            return new OidCollection() { new Oid("1.3.6.1.5.5.7.3.1"), new Oid("1.3.6.1.5.5.7.3.2") }; // Server, Client
        }

        /// <summary>
        /// Code Signing Oid Collection
        /// </summary>
        /// <returns>Code Signing</returns>
        public static OidCollection CodeSign()
        {
            return new OidCollection() { new Oid("1.3.6.1.5.5.7.3.3") }; // Code Signing
        }
    }
}
