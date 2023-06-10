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

public partial class UserDefinedFunctions
{
    [Microsoft.SqlServer.Server.SqlFunction(
        DataAccess = DataAccessKind.Read,
        FillRowMethodName = "GetServerssFiller",
        TableDefinition = @"
            objectGuid uniqueidentifier, 
            objectSid nvarchar(150) ,
            distinguishedName nvarchar(MAX), 
            canonicalName nvarchar(MAX),
            name nvarchar(255), 
            msDSisRODC int, 
            msDSisGC int, 
            serverType int,
            serverTypeText nvarchar(10),
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
    public static IEnumerable GetServers(String ldapFilter = "", String searchBase = "", String domainController = "", int resolveIpAddresses = 0)
    {
        return Common.CallImpersonated<IEnumerable>(
            () =>
            {
                ldapFilter = String.Format("(&(samAccountType=805306369)(operatingSystem=Windows*Server*){0})", ldapFilter);
                DomainController dc = PkgLdap.GetDomainController(domainController);
                List<LdapObject> items = LdapObject.GetMany(ldapFilter, "lockouttime,name,msDS-isRODC,operatingSystem,operatingSystemVersion,operatingSystemServicePack,canonicalName,dnsHostName,msDS-isGC,msDS-SiteName,serverReferenceBL,primaryGroupID,managedBy,userAccountControl,whenCreated,whenChanged,pwdLastSet", searchBase, dc);

                if (resolveIpAddresses != 0)
                {
                    Parallel.ForEach(items, item =>
                    {
                        String hostName = item.SingleValue<String>("dnsHostName");
                        item.custom1 = Common.GetIpAddress(hostName);
                    });
                }

                return items;
            }
        );
    }

    public static void GetServerssFiller(
        object config,
        out Guid objectGuid,
        out SqlString objectSid,
        out SqlString distinguishedName,
        out SqlString canonicalName,
        out SqlString name,
        out int msDSisRODC,
        out int msDSisGC,
        out int serverType,
        out SqlString serverTypeText,
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
        LdapObject lo = (LdapObject)config;
        objectGuid = new Guid(lo.guid);
        objectSid = lo.sid;
        distinguishedName = lo.SingleValue<String>("distinguishedName");
        canonicalName = lo.SingleValue<String>("canonicalName");
        name = lo.SingleValue<String>("name");
        msDSisGC = (Int16)(lo.SingleValue<Boolean>("msDS-isGC") == true ? 1 : 0);
        msDSisRODC = (Int16)(lo.SingleValue<Boolean>("msDS-isRODC") == true ? 1 : 0);
        operatingSystem = Common.strDef(lo.SingleValue<String>("operatingSystem"));
        operatingSystemVersion = Common.strDef(lo.SingleValue<String>("operatingSystemVersion"));
        operatingSystemServicePack = Common.strDef(lo.SingleValue<String>("operatingSystemServicePack"));
        dnsHostName = Common.strDef(lo.SingleValue<String>("dnsHostName"));
        msDSSiteName = lo.SingleValue<String>("msDS-SiteName");
        primaryGroupID = lo.SingleValue<int>("primaryGroupID");
        serverReferenceBL = lo.SingleValue<String>("serverReferenceBL");
        managedBy = Common.strDef(lo.SingleValue<String>("managedBy"));
        userAccountControl = lo.SingleValue<int>("userAccountControl");
        ipAddress = Common.strDef(lo.custom1);
        userAccountControlText = PkgLdap.UacToText(userAccountControl, lo.SingleValue<Int64>("lockouttime"));

        serverType = 0;
        serverTypeText = "Unknown"; 

        if (serverReferenceBL != "")
        {
            switch (primaryGroupID)
            {
                case 521:
                    {
                        serverType = 2;
                        serverTypeText = "RODC";
                    }; break;

                case 516:
                    {
                        serverType = 3;
                        serverTypeText = "RWDC";
                    }; break;
            }
        }
        else {
            serverType = 1;
            serverTypeText = "Server";        
        }

        

    }
}
