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
        FillRowMethodName = "GetUsersFiller",
        TableDefinition = @"
            objectGuid uniqueidentifier, 
            objectSid nvarchar(150) ,
            distinguishedName nvarchar(MAX),
            canonicalName nvarchar(MAX), 
            name nvarchar(255),
            samAccountName nvarchar(256),

            givenName nvarchar(64),
            middleName nvarchar(64),
            sn nvarchar(64),
            displayName nvarchar(256),
            l nvarchar(128),
            streetAddress nvarchar(1024),
            title nvarchar(128),
            userPrincipalName nvarchar(1024),
            co nvarchar(128),
            company nvarchar(64),
            department nvarchar(64),
            description nvarchar(1024),
            displayNamePrintable nvarchar(256),
            division nvarchar(256),
            employeeId nvarchar(16),
            employeeNumber nvarchar(512),
            employeeType nvarchar(256),
            homeMdb nvarchar(MAX),
            mail nvarchar(256),
            mailNickName nvarchar(64),
            physicalDeliveryOfficeName nvarchar(128),
            telephoneNumber nvarchar(64),

            primaryGroupID int, 
            managedBy nvarchar(MAX), 
            userAccountControl int,
            userAccountControlText nvarchar(1)
            "
    )]
    public static IEnumerable GetUsers(String ldapFilter = "", String attributes = "", String searchBase = "", String domainController = "")
    {
        if (attributes == "")
            attributes = "telephoneNumber,lockouttime,name,samAccountName,canonicalName,primaryGroupID,managedBy,userAccountControl,givenName,givenName,middleName,sn,displayName,l,streetAddress,title,userPrincipalName,co,company,department,description,displayNamePrintable,division,employeeId,employeeNumber,employeeType,homeMdb,mail,mailNickName,physicalDeliveryOfficeName";

        return Common.CallImpersonated<IEnumerable>(
            () =>
            {
                String user = WindowsIdentity.GetCurrent().Name.ToString(); 
                ldapFilter = String.Format("(&(samAccountType=805306368){0})", ldapFilter);
                DomainController dc = PkgLdap.GetDomainController(domainController);
                List<SearchResult> items = PkgLdap.GetUsers(ldapFilter, attributes, searchBase, dc);

                items.ForEach(item => {
                    //item.custom1 = user;// item.SingleValue<int>("userAccountControl").ToString();
                });
                
                return items;
            }
        );
    }

    public static void GetUsersFiller(
        object config,
        out Guid objectGuid,
        out SqlString objectSid,
        out SqlString distinguishedName,
        out SqlString canonicalName,
        out SqlString name,
        out SqlString samAccountName,

        out SqlString givenName,
        out SqlString middleName,
        out SqlString sn,
        out SqlString displayName,
        out SqlString l,
        out SqlString streetAddress,
        out SqlString title,
        out SqlString userPrincipalName,
        out SqlString co,
        out SqlString company,
        out SqlString department,
        out SqlString description,
        out SqlString displayNamePrintable,
        out SqlString division,
        out SqlString employeeId,
        out SqlString employeeNumber,
        out SqlString employeeType,
        out SqlString homeMdb,
        out SqlString mail,
        out SqlString mailNickName,
        out SqlString physicalDeliveryOfficeName,
        out SqlString telephoneNumber,

        out int primaryGroupID,
        out SqlString managedBy,
        out int userAccountControl,
        out SqlString userAccountControlText
    )
    {
        //LdapObject lo = (LdapObject)config;
        SearchResult sr = (SearchResult)config;
        objectGuid = PkgLdap.GetObjectGuid(sr);
        objectSid = PkgLdap.GetObjectSid(sr);
        distinguishedName = PkgLdap.GetValueOfSingleValuedAttr<String>(sr, "distinguishedName");
        canonicalName = PkgLdap.GetValueOfSingleValuedAttr<String>(sr, "canonicalName");
        name = PkgLdap.GetValueOfSingleValuedAttr<String>(sr, "name");
        samAccountName = PkgLdap.GetValueOfSingleValuedAttr<String>(sr, "samAccountName");

        givenName = Common.strDef(PkgLdap.GetValueOfSingleValuedAttr<String>(sr, "givenName"));
        middleName = Common.strDef(PkgLdap.GetValueOfSingleValuedAttr<String>(sr, "middleName"));
        sn = Common.strDef(PkgLdap.GetValueOfSingleValuedAttr<String>(sr, "sn"));
        displayName = Common.strDef(PkgLdap.GetValueOfSingleValuedAttr<String>(sr, "displayName"));
        l = Common.strDef(PkgLdap.GetValueOfSingleValuedAttr<String>(sr, "l"));
        streetAddress = Common.strDef(PkgLdap.GetValueOfSingleValuedAttr<String>(sr, "streetAddress"));
        title = Common.strDef(PkgLdap.GetValueOfSingleValuedAttr<String>(sr, "title"));
        userPrincipalName = Common.strDef(PkgLdap.GetValueOfSingleValuedAttr<String>(sr, "userPrincipalName"));
        co = Common.strDef(PkgLdap.GetValueOfSingleValuedAttr<String>(sr, "co"));
        company = Common.strDef(PkgLdap.GetValueOfSingleValuedAttr<String>(sr, "company"));
        department = Common.strDef(PkgLdap.GetValueOfSingleValuedAttr<String>(sr, "department"));
        description = Common.strDef(PkgLdap.GetValueOfSingleValuedAttr<String>(sr, "description"));
        displayNamePrintable = Common.strDef(PkgLdap.GetValueOfSingleValuedAttr<String>(sr, "displayNamePrintable"));
        division = Common.strDef(PkgLdap.GetValueOfSingleValuedAttr<String>(sr, "division"));
        employeeId = Common.strDef(PkgLdap.GetValueOfSingleValuedAttr<String>(sr, "employeeId"));
        employeeNumber = Common.strDef(PkgLdap.GetValueOfSingleValuedAttr<String>(sr, "employeeNumber"));
        employeeType = Common.strDef(PkgLdap.GetValueOfSingleValuedAttr<String>(sr, "employeeType"));
        homeMdb = Common.strDef(PkgLdap.GetValueOfSingleValuedAttr<String>(sr, "homeMdb"));
        mail = Common.strDef(PkgLdap.GetValueOfSingleValuedAttr<String>(sr, "mail"));
        mailNickName = Common.strDef(PkgLdap.GetValueOfSingleValuedAttr<String>(sr, "mailNickName"));
        physicalDeliveryOfficeName = Common.strDef(PkgLdap.GetValueOfSingleValuedAttr<String>(sr, "physicalDeliveryOfficeName"));
        telephoneNumber = Common.strDef(PkgLdap.GetValueOfSingleValuedAttr<String>(sr, "telephoneNumber"));

        primaryGroupID = PkgLdap.GetValueOfSingleValuedAttr<int>(sr, "primaryGroupID");
        managedBy = Common.strDef(PkgLdap.GetValueOfSingleValuedAttr<String>(sr, "managedBy"));
        userAccountControl = PkgLdap.GetValueOfSingleValuedAttr<int>(sr, "userAccountControl");
        userAccountControlText = PkgLdap.UacToText(userAccountControl, PkgLdap.GetValueOfSingleValuedAttr<Int64>(sr, "lockouttime"));

    }


}
