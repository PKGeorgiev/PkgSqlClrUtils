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

    protected class AttributeRec {
        public String attribute { get; set; }
        public int kind { get; set; }
    }

    [Microsoft.SqlServer.Server.SqlFunction(
        DataAccess = DataAccessKind.Read,
        FillRowMethodName = "GetQueryAttributesFiller",
        TableDefinition = @"
            attribute nvarchar(255),
            kind int            
            "
    )]
    public static IEnumerable GetQueryAttributes(String attributes = "", String domainController = "")
    {
        return Common.CallImpersonated<IEnumerable>(
            () =>
            {
                DomainController dc = PkgLdap.GetDomainController(domainController);

                String[] attrs = attributes.ToLower().Split(",".ToCharArray(), StringSplitOptions.RemoveEmptyEntries);

                String localFilter = "";

                foreach (String item in attrs) {
                    localFilter += String.Format("(ldapDisplayName={0})", item);
                }

                String ldapQuery = String.Format("(|{0})", localFilter);

                List<SearchResult> items = PkgLdap.LdapQueryMany(ldapQuery, "name,lDAPDisplayName", dc.Forest.Schema.Name, dc);

                ArrayList al = new ArrayList();
                List<String> list = new List<string>();
                items.ForEach(item => {
                    list.Add(PkgLdap.GetValueOfSingleValuedAttr<String>(item, "lDAPDisplayName").ToLower());
                });

                foreach (String attr in attrs) {
                    int knd = list.IndexOf(attr) == -1 ? 1 : 0;
                    AttributeRec ar = new AttributeRec()
                    {
                        attribute = attr,
                        kind = knd
                    };
                    al.Add(ar);
                }
                return al;
            }
        );
    }
    public static void GetQueryAttributesFiller(
        object config,
        out SqlString attribute,
        out int kind
    )
    {
        AttributeRec rec = (AttributeRec)config;
        attribute = rec.attribute;
        kind = rec.kind;
    }


}
