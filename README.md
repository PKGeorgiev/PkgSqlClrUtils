# PkgSqlClrUtils

This project contains custom CLR function for Microsoft SQL server, related to Active Directory.
These functions allow the SQL server to query directly the Active Directory for users, computers, groups etc. 
The results are populated much faster than using the AD provider via Linked Servers.

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

About CLR functions:
[CLR functions can be used to access external resources such as files, network resources, Web Services, other databases 
(including remote instances of SQL Server). This can be achieved by using various classes in the . NET Framework.](https://learn.microsoft.com/en-us/sql/relational-databases/user-defined-functions/create-clr-functions?view=sql-server-ver16)
