using System;
using System.Data;
using System.Data.SqlClient;
using System.Data.SqlTypes;
using Microsoft.SqlServer.Server;
using System.Collections;

public partial class UserDefinedFunctions
{
    [Microsoft.SqlServer.Server.SqlFunction(
        DataAccess = DataAccessKind.Read,
        FillRowMethodName = "SplitStringFiller",
        TableDefinition = "item nvarchar(1024)"
    )]
    public static IEnumerable SplitString(String StringToSplit, String Separator)
    {
        return StringToSplit.Split(Separator.ToCharArray(), StringSplitOptions.RemoveEmptyEntries);
    }

    public static void SplitStringFiller(
        object config, out SqlString item)
    {
        item = (String)config;
    }

}
