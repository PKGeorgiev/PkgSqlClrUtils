# PkgSqlClrUtils

This project contains custom CLR functions for Microsoft SQL server, related to Active Directory.
These functions allow the SQL server to query directly the Active Directory for users, computers, groups etc. 
The results are retrieved much faster than using the AD provider via Linked Servers.

List of CLR functions:
GetAttributes
GetComputers
GetDomainControllers
GetGroups
GetMembership
GetQueryAttributes
GetServers
GetUsers
SplitString

They use classes and methods located in PkgLdapUtils (the core AD library). The method LdapQueryMany uses tasks to increase the performance.

Notes:
 * You need to have a healty AD domain;
 * The computer on which resides the SQL server must be joined to your AD;
 * You have to access the SQL server / instance by using name (not IP address!);
 * All calls to domain controllers are impersonated (i.e. they run as the authenticated user);
 * In general the SQL assemblies must be signed. If you're testing with unsigned assembly, your database must be marked as trustworthy:
   ALTER DATABASE [DB_NAME_HERE]
     SET TRUSTWORTHY ON
     WITH ROLLBACK IMMEDIATE 

About CLR functions:
[CLR functions can be used to access external resources such as files, network resources, Web Services, other databases 
(including remote instances of SQL Server). This can be achieved by using various classes in the . NET Framework.](https://learn.microsoft.com/en-us/sql/relational-databases/user-defined-functions/create-clr-functions?view=sql-server-ver16)

Please note that this is an old project of mine and the source code may not conform current trends in naming conventions. Also some parts of the code may need to be refactored. 
