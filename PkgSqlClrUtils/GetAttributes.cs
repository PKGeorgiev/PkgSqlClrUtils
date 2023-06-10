using System;
using System.Data;
using System.Data.SqlClient;
using System.Data.SqlTypes;
using Microsoft.SqlServer.Server;
using System.Collections;
using System.DirectoryServices.ActiveDirectory;
using System.Collections.Generic;
using PkgLdapUtils;
using PkgSqlClrUtils;
using System.Security.Principal;
using System.DirectoryServices;

public partial class UserDefinedFunctions
{
    [Microsoft.SqlServer.Server.SqlFunction(
        DataAccess = DataAccessKind.Read,
        FillRowMethodName = "GetAttributesFiller",
        TableDefinition = @"
            objectGuid uniqueidentifier, 
            distinguishedName nvarchar(MAX),
            name nvarchar(255),
            lDAPDisplayName nvarchar(256)            
            "
    )]
    public static IEnumerable GetAttributes(String ldapFilter = "", String domainController = "")
    {
        return Common.CallImpersonated<IEnumerable>(
            () =>
            {
                DomainController dc = PkgLdap.GetDomainController(domainController);

                List<SearchResult> items = PkgLdap.LdapQueryMany(ldapFilter, "name,lDAPDisplayName", dc.Forest.Schema.Name, dc);

                /*items.ForEach(item =>
                {
                    //item.custom1 = user;// item.SingleValue<int>("userAccountControl").ToString();
                });*/

                return items;
            }
        );
    }

    public static void GetAttributesFiller(
        object config,
        out Guid objectGuid,
        out SqlString distinguishedName,
        out SqlString name,
        out SqlString lDAPDisplayName
    )
    {
        SearchResult sr = (SearchResult)config;
        objectGuid = PkgLdap.GetObjectGuid(sr);
        distinguishedName = PkgLdap.GetValueOfSingleValuedAttr<String>(sr, "distinguishedName");
        name = PkgLdap.GetValueOfSingleValuedAttr<String>(sr, "name");

        lDAPDisplayName = Common.strDef(PkgLdap.GetValueOfSingleValuedAttr<String>(sr, "lDAPDisplayName"));

    }


}
