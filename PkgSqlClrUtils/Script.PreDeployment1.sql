/*
 Pre-Deployment Script Template							
--------------------------------------------------------------------------------------
 This file contains SQL statements that will be executed before the build script.	
 Use SQLCMD syntax to include a file in the pre-deployment script.			
 Example:      :r .\myfile.sql								
 Use SQLCMD syntax to reference a variable in the pre-deployment script.		
 Example:      :setvar TableName MyTable							
               SELECT * FROM [$(TableName)]					
--------------------------------------------------------------------------------------
*/
--EXEC sp_changedbowner 'sa';
--if exists(select * from sys.assemblies where name = 'System.Directoryservices')
--drop assembly [System.Directoryservices]

create assembly [System.Directoryservices]
from 'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\System.Directoryservices.dll'
with permission_set = unsafe;
go

EXEC sp_configure 'clr enabled', 1;
GO
RECONFIGURE;
GO