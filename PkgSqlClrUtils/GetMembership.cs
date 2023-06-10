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
        FillRowMethodName = "GetMembershipFiller",
        TableDefinition = @"
            objectGuid uniqueidentifier, 
            objectSid nvarchar(150) ,
            distinguishedName nvarchar(MAX),
            canonicalName nvarchar(MAX), 
            name nvarchar(255),
            samAccountName nvarchar(256),

            displayName nvarchar(256),
            description nvarchar(1024),
            mail nvarchar(256),
            mailNickName nvarchar(64),
            
            groupScope nvarchar(20),
            groupType bigint,
            groupTypeText nvarchar(20),
            samAccountType int,

            managedBy nvarchar(MAX)          
            "
    )]
    public static IEnumerable GetMembership(String samAccountName, String attributes = "", String domainController = "")
    {
        return Common.CallImpersonated<IEnumerable>(
            () =>
            {

                if (attributes == "")
                    attributes = "groupType,sAMAccountType,name,samAccountName,canonicalName,managedBy,displayName,description,mail,mailNickName";

                DomainController dc = PkgLdap.GetDomainController(domainController);
                SearchResult srAccount = PkgLdapUtils.PkgLdap.GetAccount(String.Format("(samAccountName={0})", samAccountName), "", "", dc);

                List<SearchResult> items = PkgLdap.GetMembership(srAccount, attributes, "", dc);

                return items;
            }
        );
    }

    public static void GetMembershipFiller(
        object config,
        out Guid objectGuid,
        out SqlString objectSid,
        out SqlString distinguishedName,
        out SqlString canonicalName,
        out SqlString name,
        out SqlString samAccountName,

        out SqlString displayName,
        out SqlString description,
        out SqlString mail,
        out SqlString mailNickName,
        out SqlString groupScope,
        out Int64 groupType,
        out SqlString groupTypeText,
        out int samAccountType,

        out SqlString managedBy
    )
    {
        SearchResult sr = (SearchResult)config;
        objectGuid = PkgLdap.GetObjectGuid(sr);
        objectSid = PkgLdap.GetObjectSid(sr);
        distinguishedName = PkgLdap.GetValueOfSingleValuedAttr<String>(sr, "distinguishedName");
        canonicalName = PkgLdap.GetValueOfSingleValuedAttr<String>(sr, "canonicalName");
        name = PkgLdap.GetValueOfSingleValuedAttr<String>(sr, "name");
        samAccountName = PkgLdap.GetValueOfSingleValuedAttr<String>(sr, "samAccountName");

        displayName = Common.strDef(PkgLdap.GetValueOfSingleValuedAttr<String>(sr, "displayName"));
        description = Common.strDef(PkgLdap.GetValueOfSingleValuedAttr<String>(sr, "description"));
        mail = Common.strDef(PkgLdap.GetValueOfSingleValuedAttr<String>(sr, "mail"));
        mailNickName = Common.strDef(PkgLdap.GetValueOfSingleValuedAttr<String>(sr, "mailNickName"));

        managedBy = Common.strDef(PkgLdap.GetValueOfSingleValuedAttr<String>(sr, "managedBy"));

        groupType = PkgLdap.GetValueOfSingleValuedAttr<Int64>(sr, "groupType");
        samAccountType = PkgLdap.GetValueOfSingleValuedAttr<int>(sr, "sAMAccountType");

        groupTypeText = PkgLdapUtils.PkgLdap.GetGroupTypeText(groupType);// "?";
        groupScope = PkgLdapUtils.PkgLdap.GetGroupScopeText(groupType, samAccountType);// "?";

    }


}
