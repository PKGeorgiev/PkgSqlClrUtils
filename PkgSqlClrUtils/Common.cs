using System;
using System.Collections.Generic;
using System.Text;
using Microsoft.SqlServer.Server;
using System.Security.Principal;
using System.Net;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.DirectoryServices;

namespace PkgSqlClrUtils
{

    class DataItem {
        
        public String Item1 { get; set; }
    }

    public static class SearchResultExtension
    {
        //ConditionalWeakTable is available in .NET 4.0+
        //if you use an older .NET, you have to create your own CWT implementation (good luck with that!)
        static readonly ConditionalWeakTable<SearchResult, Dictionary<String, Object>> Flags = new ConditionalWeakTable<SearchResult, Dictionary<String, Object>>();

        public static Dictionary<String, object> GetDict(SearchResult sr)
        {
            Dictionary<String, Object> d = null;
            if (!Flags.TryGetValue(sr, out d))
            {
                d = new Dictionary<string, object>();
                Flags.Add(sr, d);
            }

            return d;
        }

        public static void SetData(this SearchResult sr, String key, Object value){
            Dictionary<String, Object> d = GetDict(sr);
            d[key] = value;
        }

        public static object GetData(this SearchResult sr, String key){
            object data = null;
            Dictionary<String, Object> d = GetDict(sr);
            if (d.ContainsKey(key))
                data = d[key];
            return data;
        }
        
    }

    class Common
    {
        public static T CallImpersonated<T>(Func<T> action) { 
                
            WindowsImpersonationContext impersonatedUser = null;
            WindowsIdentity clientId = null;

            try
            {

                clientId = SqlContext.WindowsIdentity;

                if (clientId != null)
                {
                    impersonatedUser = clientId.Impersonate();
                    if (impersonatedUser != null)
                    {
                        return action();
                    }
                    else {
                        throw new Exception(String.Format("Unable to impersonate {0}!", clientId.Name));
                    }
                }
                else
                    throw new Exception("Unable to get SqlContext.WindowsIdentity!");

            }
            finally
            {
                if (impersonatedUser != null)
                    impersonatedUser.Undo();
            }


        }

        public static string GetIpAddress(string hostName)
        {
            if (hostName != String.Empty & hostName != null)
                try
                {
                    IPHostEntry entry = Dns.GetHostEntry(hostName);
                    if (entry != null)
                    {
                        if (entry.AddressList.Length == 0)
                            throw new Exception(String.Format("Unable to find IPAddress for host: {0}", hostName));
                        else
                            return entry.AddressList[0].ToString();

                    }
                }
                catch (SocketException ex)
                {
                    //unknown host or
                    //not every IP has a name
                    //log exception (manage it)
                    //throw;
                }

            return "?";
        }

        public static string GetHostName(string ipAddress)
        {
            try
            {
                IPHostEntry entry = Dns.GetHostEntry(ipAddress);
                if (entry != null)
                {
                    return entry.HostName;
                }
            }
            catch (SocketException ex)
            {
                //unknown host or
                //not every IP has a name
                //log exception (manage it)
            }

            return "?";
        }

        public static String strDef(String theString, String defaultValue = null) {
            if (String.IsNullOrEmpty(theString))
                return defaultValue;
            else
                return theString;
        }

    }
}
