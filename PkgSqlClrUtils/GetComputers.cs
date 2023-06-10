using System;
using System.Data;
using System.Data.SqlClient;
using System.Data.SqlTypes;
using Microsoft.SqlServer.Server;
using PkgSqlClrUtils;
using System.Collections;
using PkgLdapUtils;
using System.Collections.Generic;
using System.DirectoryServices.ActiveDirectory;
using System.Threading.Tasks;
using System.DirectoryServices;

public partial class UserDefinedFunctions
{
    [Microsoft.SqlServer.Server.SqlFunction(
        DataAccess = DataAccessKind.Read,
        FillRowMethodName = "GetComputersFiller",
        TableDefinition = @"
            objectGuid uniqueidentifier, 
            objectSid nvarchar(150) ,
            distinguishedName nvarchar(MAX), 
            canonicalName nvarchar(MAX),
            name nvarchar(255), 
            operatingSystem nvarchar(255), 
            operatingSystemVersion nvarchar(255), 
            operatingSystemServicePack nvarchar(255), 
            dnsHostName nvarchar(2048), 
            primaryGroupID int, 
            managedBy nvarchar(MAX), 
            userAccountControl int,
            userAccountControlText nvarchar(1),
            ipAddress nvarchar(50),
            pwdLastSet datetime2(7)
            "
    )]
    public static IEnumerable GetComputers(String ldapFilter = "", String attributes = "", String searchBase = "", String domainController = "", int resolveIpAddresses = 0)
    {
        return Common.CallImpersonated<IEnumerable>(
            () =>
            {
                if (attributes == "")
                    attributes = "lockouttime,name,msDS-isRODC,operatingSystem,operatingSystemVersion,operatingSystemServicePack,canonicalName,dnsHostName,msDS-isGC,msDS-SiteName,serverReferenceBL,primaryGroupID,managedBy,userAccountControl,whenCreated,whenChanged,pwdLastSet";

                //ldapFilter = String.Format("(&(samAccountType=805306369)(!primaryGroupID=521)(!primaryGroupID=516){0})", ldapFilter);
                DomainController dc = PkgLdap.GetDomainController(domainController);
                List<SearchResult> items = PkgLdap.GetComputers(ldapFilter, attributes, searchBase, dc);

                if (resolveIpAddresses != 0)
                {
                    Parallel.ForEach(items, item =>
                    {
                        String hostName = PkgLdap.GetValueOfSingleValuedAttr<String>(item, "dnsHostName");
                        item.SetData("ip", Common.GetIpAddress(hostName));
                    });
                }

                return items;
            }
        );
    }

    public static void GetComputersFiller(
        object config,
        out Guid objectGuid,
        out SqlString objectSid,
        out SqlString distinguishedName,
        out SqlString canonicalName,
        out SqlString name,
        out SqlString operatingSystem,
        out SqlString operatingSystemVersion,
        out SqlString operatingSystemServicePack,
        out SqlString dnsHostName,
        out int primaryGroupID,
        out SqlString managedBy,
        out int userAccountControl,
        out SqlString userAccountControlText,
        out SqlString ipAddress,
        out DateTime pwdLastSet
    )
    {
        SearchResult sr = (SearchResult)config;
        objectGuid = PkgLdap.GetObjectGuid(sr);
        objectSid = PkgLdap.GetObjectSid(sr);
        distinguishedName = PkgLdap.GetValueOfSingleValuedAttr<String>(sr, "distinguishedName");
        canonicalName = PkgLdap.GetValueOfSingleValuedAttr<String>(sr, "canonicalName");
        name = PkgLdap.GetValueOfSingleValuedAttr<String>(sr, "name");
        operatingSystem = Common.strDef(PkgLdap.GetValueOfSingleValuedAttr<String>(sr, "operatingSystem"));
        operatingSystemVersion = Common.strDef(PkgLdap.GetValueOfSingleValuedAttr<String>(sr, "operatingSystemVersion"));
        operatingSystemServicePack = Common.strDef(PkgLdap.GetValueOfSingleValuedAttr<String>(sr, "operatingSystemServicePack"));
        dnsHostName = Common.strDef(PkgLdap.GetValueOfSingleValuedAttr<String>(sr, "dnsHostName"));
        primaryGroupID = PkgLdap.GetValueOfSingleValuedAttr<int>(sr, "primaryGroupID");
        managedBy = Common.strDef(PkgLdap.GetValueOfSingleValuedAttr<String>(sr, "managedBy"));
        userAccountControl = PkgLdap.GetValueOfSingleValuedAttr<int>(sr, "userAccountControl");
        ipAddress = Common.strDef((string)sr.GetData("ip"));
        userAccountControlText = PkgLdap.UacToText(userAccountControl, PkgLdap.GetValueOfSingleValuedAttr<Int64>(sr, "lockouttime"));
        pwdLastSet = DateTime.FromFileTime(PkgLdap.GetValueOfSingleValuedAttr<Int64>(sr, "pwdLastSet"));
    }


}
