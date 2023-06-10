using System;
using System.Data;
using System.Data.SqlClient;
using System.Data.SqlTypes;
using Microsoft.SqlServer.Server;
using PkgLdapUtils;
using System.Collections.Generic;
using System.Collections;
using System.DirectoryServices.ActiveDirectory;
using System.Security.Principal;
using PkgSqlClrUtils;
using System.Threading.Tasks;
using System.DirectoryServices;
using System.Runtime.CompilerServices;

public partial class UserDefinedFunctions
{
    [Microsoft.SqlServer.Server.SqlFunction(
        DataAccess = DataAccessKind.Read,
        FillRowMethodName = "GetDomainControllersFiller",
        TableDefinition = @"
            objectGuid uniqueidentifier, 
            objectSid nvarchar(150) ,
            distinguishedName nvarchar(MAX), 
            canonicalName nvarchar(MAX),
            name nvarchar(255), 
            msDSisRODC int, 
            msDSisGC int, 
            operatingSystem nvarchar(255), 
            operatingSystemVersion nvarchar(255), 
            operatingSystemServicePack nvarchar(255), 
            dnsHostName nvarchar(2048), 
            msDSSiteName nvarchar(MAX), 
            primaryGroupID int, 
            serverReferenceBL nvarchar(MAX), 
            managedBy nvarchar(MAX), 
            userAccountControl int,
            userAccountControlText nvarchar(1),
            ipAddress nvarchar(50)"
    )]
    public static IEnumerable GetDomainControllers(String ldapFilter = "", String searchBase = "", String domainController = "", int resolveIpAddresses = 0)
    {

        try
        {
            
        }
        catch { };

        //ConditionalWeakTable<SearchResult, Tuple<String>> ExData = new ConditionalWeakTable<SearchResult, Tuple<String>>();
        
        return Common.CallImpersonated<IEnumerable>(
            () => {
                //ldapFilter = String.Format("(&(samAccountType=805306369)(|(primaryGroupID=521)(primaryGroupID=516)){0})", ldapFilter);
                DomainController dc = PkgLdap.GetDomainController(domainController);
                List<SearchResult> items = PkgLdapUtils.PkgLdap.GetDcs(ldapFilter, "lockouttime,name,msDS-isRODC,operatingSystem,operatingSystemVersion,operatingSystemServicePack,canonicalName,dnsHostName,msDS-isGC,msDS-SiteName,serverReferenceBL,primaryGroupID,managedBy,userAccountControl,whenCreated,whenChanged,pwdLastSet", searchBase, dc);

                if (resolveIpAddresses != 0)
                {
                    Parallel.ForEach(items, item =>
                    {
                        PkgSqlClrUtils.DataItem di = new PkgSqlClrUtils.DataItem();
                        
                        String hostName = PkgLdap.GetValueOfSingleValuedAttr<String>(item, "dnsHostName");
                        item.SetData("ip", Common.GetIpAddress(hostName));
                    });
                }

                return items;        
            }
        );
    }

    public static void GetDomainControllersFiller(
        object config,
        out Guid objectGuid,
        out SqlString objectSid,
        out SqlString distinguishedName,
        out SqlString canonicalName,
        out SqlString name,
        out int msDSisRODC,
        out int msDSisGC,
        out SqlString operatingSystem,
        out SqlString operatingSystemVersion,
        out SqlString operatingSystemServicePack,
        out SqlString dnsHostName,
        out SqlString msDSSiteName,
        out int primaryGroupID,
        out SqlString serverReferenceBL,
        out SqlString managedBy,
        out int userAccountControl,
        out SqlString userAccountControlText,
        out SqlString ipAddress
    )
    {
        //LdapObject lo = (LdapObject)config;
        SearchResult sr = (SearchResult)config;
        objectGuid = PkgLdap.GetObjectGuid(sr);
        objectSid = PkgLdap.GetObjectSid(sr);
        distinguishedName = PkgLdap.GetValueOfSingleValuedAttr<String>(sr, "distinguishedName");
        canonicalName = PkgLdap.GetValueOfSingleValuedAttr<String>(sr, "canonicalName");
        name = PkgLdap.GetValueOfSingleValuedAttr<String>(sr, "name");
        msDSisGC = (Int16)(PkgLdap.GetValueOfSingleValuedAttr<Boolean>(sr, "msDS-isGC") == true ? 1 : 0);
        msDSisRODC = (Int16)(PkgLdap.GetValueOfSingleValuedAttr<Boolean>(sr, "msDS-isRODC") == true ? 1 : 0);
        operatingSystem = Common.strDef(PkgLdap.GetValueOfSingleValuedAttr<String>(sr, "operatingSystem"));
        operatingSystemVersion = Common.strDef(PkgLdap.GetValueOfSingleValuedAttr<String>(sr, "operatingSystemVersion"));
        operatingSystemServicePack = Common.strDef(PkgLdap.GetValueOfSingleValuedAttr<String>(sr, "operatingSystemServicePack"));
        dnsHostName = Common.strDef(PkgLdap.GetValueOfSingleValuedAttr<String>(sr, "dnsHostName"));
        msDSSiteName = PkgLdap.GetValueOfSingleValuedAttr<String>(sr, "msDS-SiteName");
        primaryGroupID = PkgLdap.GetValueOfSingleValuedAttr<int>(sr, "primaryGroupID");
        serverReferenceBL = PkgLdap.GetValueOfSingleValuedAttr<String>(sr, "serverReferenceBL");
        managedBy = Common.strDef(PkgLdap.GetValueOfSingleValuedAttr<String>(sr, "managedBy"));
        userAccountControl = PkgLdap.GetValueOfSingleValuedAttr<int>(sr, "userAccountControl");
        ConditionalWeakTable<SearchResult, Tuple<String>> ExData = new ConditionalWeakTable<SearchResult, Tuple<String>>();
        ipAddress = Common.strDef((string)sr.GetData("ip"));
        userAccountControlText = PkgLdap.UacToText(userAccountControl, PkgLdap.GetValueOfSingleValuedAttr<Int64>(sr, "lockouttime"));
    }
}
