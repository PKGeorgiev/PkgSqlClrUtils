using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.DirectoryServices.ActiveDirectory;
using System.DirectoryServices;
using System.Security.Principal;
using System.Security.AccessControl;

namespace PkgLdapUtils
{
    public static class Globals
    {
        public const int SAM_GROUP_OBJECT = 0x10000000;
        public const int SAM_NON_SECURITY_GROUP_OBJECT = 0x10000001;
        public const int SAM_ALIAS_OBJECT = 0x20000000;
        public const int SAM_NON_SECURITY_ALIAS_OBJECT = 0x20000001;
        public const int SAM_USER_OBJECT = 0x30000000;
        public const int SAM_MACHINE_ACCOUNT = 0x30000001;
        public const int SAM_TRUST_ACCOUNT = 0x30000002;
        public const int ADS_UF_DONT_EXPIRE_PASSWD = 65536;
        public const int ADS_UF_PASSWD_CANT_CHANGE = 64;
    }

    public class LdapObject
    {
        protected SearchResult _sr { get; set; }
        protected DomainController _domainController { get; set; }
        public string custom1 { get; set; }
        public string guid { get; set; }
        public string dn { get; set; }
        public string sid
        {
            get
            {
                byte[] sidBytes = PkgLdap.GetValueOfSingleValuedAttr<byte[]>(_sr, "objectSid");
                if (sidBytes.Length > 0)
                    return (new SecurityIdentifier(sidBytes, 0)).ToString();
                else
                    return string.Empty;
            }
            set { }
        }

        public DirectoryEntry directoryEntry { get { return _sr.GetDirectoryEntry(); } set { } }

        public LdapObject(SearchResult searchResult, DomainController domainController)
        {
            if (searchResult == null)
                throw new Exception("searchResult cannot be null!");
            _sr = searchResult;
            _domainController = domainController;
            initialize();
            //custom1 = WindowsIdentity.GetCurrent().Name.ToString();
        }

        protected void initialize()
        {
            dn = PkgLdap.GetValueOfSingleValuedAttr<string>(_sr, "distinguishedName");
            guid = (new Guid(PkgLdap.GetValueOfSingleValuedAttr<byte[]>(_sr, "objectGuid"))).ToString();
        }

        public void CheckProperty(string property)
        {
            if (!HasProperty(property))
                throw new Exception(string.Format("Property [{0}] was not found!", property));
        }

        public Boolean HasProperty(string property)
        {
            property = property.ToLower();
            foreach (var attr in _sr.Properties.PropertyNames)
            {
                if (attr.ToString().ToLower() == property)
                    return true;
            }
            return false;
        }

        public T SingleValue<T>(string propertyName)
        {
            return PkgLdap.GetValueOfSingleValuedAttr<T>(_sr, propertyName);
        }

        public List<T> MultiValue<T>(string propertyName)
        {
            return PkgLdap.GetValueOfMultiValuedAttr<T>(_sr, propertyName);
        }

        public static LdapObject Get(string distinguishedName, string attributes = "", String searchBase = "", DomainController domainController = null)
        {
            return GetOne(string.Format("(distinguishedName={0})", distinguishedName), attributes, searchBase, domainController);
        }

        public static LdapObject GetOne(string ldapFilter, string attributes = "", String searchBase = "", DomainController domainController = null)
        {
            SearchResult sr = PkgLdap.LdapQueryOne(ldapFilter, attributes, searchBase, domainController);
            return new LdapObject(sr, domainController);
        }

        public static List<LdapObject> GetMany(string ldapFilter, string attributes = "", String searchBase = "", DomainController domainController = null)
        {
            List<LdapObject> items = new List<LdapObject>();

            List<SearchResult> src = PkgLdap.LdapQueryMany(ldapFilter, attributes, searchBase, domainController);
            foreach (SearchResult sr in src)
            {
                LdapObject lo = new LdapObject(sr, domainController);
                items.Add(lo);
            }

            return items;
        }

        public static List<LdapObject> TransformList(List<SearchResult> list, DomainController domainController)
        {
            List<LdapObject> loList = new List<LdapObject>();
            foreach (SearchResult sr in list)
            {
                loList.Add(new LdapObject(sr, domainController));
            }
            return loList;
        }

        public static List<LdapObject> GetGroups(string ldapFilter, string attributes = "", String searchBase = "", DomainController domainController = null)
        {
            ldapFilter = string.Format("(&(|(SamAccountType={0})(SamAccountType={1})(SamAccountType={2})){3})", 268435456, 268435457, 536870912, ldapFilter);
            return TransformList(PkgLdap.GetGroups(ldapFilter, attributes, searchBase, domainController), domainController);
        }


        public static LdapObject GetUser(string property, string value, string attributes = "", String searchBase = "", DomainController domainController = null)
        {
            string ldapFilter = string.Format("(&(SamAccountType={0})({1}={2}))", 805306368, property, value);
            SearchResult sr = PkgLdap.LdapQueryOne(ldapFilter, attributes, searchBase, domainController);
            return new LdapObject(sr, domainController);
        }

        public static LdapObject GetGroup(string property, string value, string attributes = "", String searchBase = "", DomainController domainController = null)
        {
            string ldapFilter = string.Format("(&(|(SamAccountType={0})(SamAccountType={1})(SamAccountType={2}))({3}={4}))", 268435456, 268435457, 536870912, property, value);
            SearchResult sr = PkgLdap.LdapQueryOne(ldapFilter, attributes, searchBase, domainController);
            return new LdapObject(sr, domainController);
        }

        public static LdapObject GetComputer(string property, string value, string attributes = "", String searchBase = "", DomainController domainController = null)
        {
            string ldapFilter = string.Format("(&(SamAccountType={0})({1}={2}))", 805306369, property, value);
            SearchResult sr = PkgLdap.GetComputer(ldapFilter, attributes, searchBase, domainController);
            return new LdapObject(sr, domainController);
        }

        public static LdapObject GetAccount(string property, string value, string attributes = "", String searchBase = "", DomainController domainController = null)
        {
            string ldapFilter = string.Format("(&(|(SamAccountType={0})(objectCategory={1}))({2}={3}))", 805306368, "Group", property, value);
            SearchResult sr = PkgLdap.LdapQueryOne(ldapFilter, attributes, searchBase, domainController);
            return new LdapObject(sr, domainController);
        }

        public void Refresh()
        {
            List<string> attrs = new List<string>();
            foreach (string attr in this._sr.Properties.PropertyNames)
            {
                attrs.Add(attr);
            }
            SearchResult sr = PkgLdap.LdapQueryOne(new Guid(guid), string.Join(",", attrs), _domainController);
            this._sr = sr;
            initialize();
        }

        public string GetAdsPathGuid(DomainController domainController = null)
        {
            //if (domainController == null)
            //domainController = GetDom

            return string.Format("LDAP://{0}/<GUID={1}>", domainController.Name, guid);
        }

        public string GetWritableAdsPathGuid(DomainController domainController = null)
        {


            return string.Format("LDAP://{0}/<GUID={1}>", domainController.Name, guid);
        }

        public DirectoryEntry GetNewDirectoryEntry(DomainController domainController = null)
        {
            return new DirectoryEntry(GetAdsPathGuid(domainController));
        }
    }

    class PkgLdap
    {
        public static String[] mainAttributes = new String[] { 
            "distinguishedname",
            "objectguid",
            "objectsid",
            "name",
            "samAccountType"
        };

        public static T GetValueOfSingleValuedAttr<T>(SearchResult sr, string propertyName)
        {
            ResultPropertyValueCollection pvc = sr.Properties[propertyName];
            return pvc.Count > 0 ? (T)Convert.ChangeType(pvc[0], typeof(T)) : default(T);
        }

        public static List<T> GetValueOfMultiValuedAttr<T>(SearchResult sr, string propertyName)
        {
            ResultPropertyValueCollection pvc = sr.Properties[propertyName];
            List<T> lst = new List<T>();
            foreach (T s in pvc)
            {
                lst.Add(s);
            }
            return lst;
        }

        public static DirectorySearcher GetDirectorySearcher(DomainController domainController = null)
        {
            domainController = GetDomainController(domainController);
            DirectorySearcher ds = domainController.GetDirectorySearcher();
            return ds;
        }

        protected static List<SearchResult> LdapQueryManyInternal(string ldapFilter, String attributes = "", String searchBase = "", DomainController domainController = null)
        {
            List<SearchResult> items = new List<SearchResult>();
            DirectorySearcher ds = GetDirectorySearcher(domainController);
            string[] attrs = attributes.Split(",".ToCharArray(), StringSplitOptions.RemoveEmptyEntries);
            ds.PropertiesToLoad.AddRange(attrs);
            ds.PageSize = 1000;
            if (searchBase != "")
            {
                string sb = string.Format("LDAP://{0}/{1}", domainController.Name, searchBase);
                ds.SearchRoot = new DirectoryEntry(sb);
            }
            ds.Filter = ldapFilter;

            foreach (SearchResult sr in ds.FindAll())
            {
                items.Add(sr);
            }

            return items;
        }

        public static List<SearchResult> LdapQueryMany(string ldapFilter, string attributes = "", String searchBase = "", DomainController domainController = null)
        {
            List<SearchResult> items = new List<SearchResult>();

            attributes = AddAttributes(attributes);
            domainController = GetDomainController(domainController);
            List<string> distinguishedNames = new List<string>();
            List<Task<List<SearchResult>>> tasks = new List<Task<List<SearchResult>>>();

            distinguishedNames.AddRange(searchBase.Split("^".ToCharArray(), StringSplitOptions.RemoveEmptyEntries));

            if (distinguishedNames.Count == 0)
                distinguishedNames.Add("");

            //  Capture current windows identity
            //  http://stackoverflow.com/questions/16149422/how-do-i-set-the-user-identity-for-tasks-when-calling-task-waitall
            //  http://stackoverflow.com/questions/26065155/parallel-foreach-changes-impersonation-context
            IntPtr token = WindowsIdentity.GetCurrent().Token;

            //return LdapQueryManyInternal(ldapFilter, attributes, searchBase, domainController);
            //  Spawn new searcher for each distinguishedname
            foreach (string dn in distinguishedNames)
            {
                Task<List<SearchResult>> task = Task.Factory.StartNew<List<SearchResult>>(() =>
                {
                    using (WindowsIdentity.Impersonate(token))
                    {
                        return LdapQueryManyInternal(ldapFilter, attributes, dn, domainController);
                    };
                });
                tasks.Add(task);
            }

            //  Wait all tasks to complete
            Task.WaitAll(tasks.ToArray());

            // Union the results
            tasks.ForEach(item => { items.AddRange(item.Result); });

            return items;
        }

        public static void CheckSearchResult(SearchResult searchResult, string ldapFilter)
        {
            if (searchResult == null)
                throw new Exception(string.Format("Unable to find Directory Entry with ldap filter: [{0}]", ldapFilter));
        }

        public static SearchResult LdapQueryOne(string ldapFilter, string attributes = "", String searchBase = "", DomainController domainController = null)
        {
            domainController = GetDomainController(domainController);
            attributes = AddAttributes(attributes);
            DirectorySearcher ds = GetDirectorySearcher(domainController);
            string[] attrs = attributes.Split(",".ToCharArray(), StringSplitOptions.RemoveEmptyEntries);
            ds.PropertiesToLoad.AddRange(attrs);
            ds.Filter = ldapFilter;
            if (searchBase != "")
            {
                string sb = string.Format("LDAP://{0}/{1}", domainController.Name, searchBase);
                ds.SearchRoot = new DirectoryEntry(sb);
            }
            SearchResult sr = ds.FindOne();
            CheckSearchResult(sr, ldapFilter);
            return sr;
        }

        public static SearchResult LdapQueryOneBase(string entity, string attributes = "", DomainController domainController = null)
        {
            attributes = AddAttributes(attributes);
            DirectorySearcher ds = GetDirectorySearcher(domainController);
            string[] attrs = attributes.Split(",".ToCharArray(), StringSplitOptions.RemoveEmptyEntries);
            entity = string.Format("{0}/{1}", ds.SearchRoot.Path, entity);
            ds.SearchRoot = new DirectoryEntry(entity);
            ds.PropertiesToLoad.AddRange(attrs);
            ds.Filter = "(objectCategory=*)";
            SearchResult sr = ds.FindOne();
            CheckSearchResult(sr, entity);
            return sr;
        }

        public static SearchResult LdapQueryOne(SecurityIdentifier sid, string attributes = "", DomainController domainController = null)
        {
            string adsPath = string.Format("<SID={0}>", sid.ToString());
            return LdapQueryOneBase(adsPath, attributes, domainController);
        }

        public static SearchResult LdapQueryOne(Guid guid, string attributes = "", DomainController domainController = null)
        {
            string adsPath = string.Format("<GUID={0}>", guid.ToString());
            return LdapQueryOneBase(adsPath, attributes, domainController);
        }

        public static DomainController GetDomainController(string name = "", LocatorOptions locatorOptions = 0, String username = "", String password = "")
        {
            if (name != "")
            {
                DirectoryContext ctx;
                if (username != "" && password != "")
                    ctx = new DirectoryContext(DirectoryContextType.DirectoryServer, name, username, password);
                else
                    ctx = new DirectoryContext(DirectoryContextType.DirectoryServer, name);
                return DomainController.GetDomainController(ctx);
            }
            else
            {
                Domain dom = Domain.GetComputerDomain();
                return dom.FindDomainController(locatorOptions);
            }
        }

        public static DomainController GetDomainController(DomainController domainController)
        {
            if (domainController == null)
                return GetDomainController("", 0);
            else
                return domainController;
        }

        public static DomainController GetWritableDomainController(DomainController givenDomainController = null, String username = "", String password = "")
        {
            if (givenDomainController == null)
                return GetDomainController("", LocatorOptions.WriteableRequired, username, password);
            else
            {
                CheckWritableDomainController(givenDomainController);
                return givenDomainController;
            }

        }

        public static string SidToOctetString(SecurityIdentifier sid)
        {
            string g = string.Empty;
            byte[] bytes = new byte[sid.BinaryLength];
            sid.GetBinaryForm(bytes, 0);

            foreach (var b in bytes)
            {
                g += string.Format("{0:X2}", b);
            }

            return g;
        }

        public static string AddAttributes(string attributes)
        {
            attributes = attributes.ToLower();
            List<string> resultantAttrs = new List<string>();
            resultantAttrs.AddRange(mainAttributes);
            HashSet<string> hs = new HashSet<string>(mainAttributes);
            hs.UnionWith(attributes.Split(",".ToCharArray(), StringSplitOptions.RemoveEmptyEntries));
            attributes = string.Join(",", hs.ToArray<string>());
            return attributes;
        }

        public static Guid GetObjectGuid(SearchResult searchResult)
        {
            byte[] bytes = PkgLdap.GetValueOfSingleValuedAttr<byte[]>(searchResult, "objectGuid");
            if (bytes.Length > 0)
                return new Guid(bytes);
            else
                throw new Exception(string.Format("Unable to find objectGuid for {0}", PkgLdap.GetValueOfSingleValuedAttr<byte[]>(searchResult, "distinguishedName")));
        }

        public static string GetObjectSid(SearchResult searchResult)
        {
            byte[] sidBytes = PkgLdap.GetValueOfSingleValuedAttr<byte[]>(searchResult, "objectSid");
            if (sidBytes.Length > 0)
                return (new SecurityIdentifier(sidBytes, 0)).ToString();
            else
                return string.Empty;
        }

        public static SearchResult GetUser(string ldapFilter, string attributes = "", string searchBase = "", DomainController domainController = null)
        {
            ldapFilter = string.Format("(&(samAccountType={0}){1})", 805306368, ldapFilter);
            return LdapQueryOne(ldapFilter, attributes, searchBase, domainController);
        }

        public static List<SearchResult> GetUsers(string ldapFilter, string attributes = "", string searchBase = "", DomainController domainController = null)
        {
            ldapFilter = string.Format("(&(samAccountType={0}){1})", 805306368, ldapFilter);
            return LdapQueryMany(ldapFilter, attributes, searchBase, domainController);
        }

        public static SearchResult GetAccount(string ldapFilter, string attributes = "", string searchBase = "", DomainController domainController = null)
        {
            ldapFilter = string.Format("(&(|(samAccountType={0})(samAccountType={1})){2})", 805306368, 805306369, ldapFilter);
            return LdapQueryOne(ldapFilter, attributes, searchBase, domainController);
        }

        public static List<SearchResult> GetAccounts(string ldapFilter, string attributes = "", string searchBase = "", DomainController domainController = null)
        {
            ldapFilter = string.Format("(&(|(samAccountType={0})(samAccountType={1})){2})", 805306368, 805306369, ldapFilter);
            return LdapQueryMany(ldapFilter, attributes, searchBase, domainController);
        }

        public static SearchResult GetGroup(string ldapFilter, string attributes = "", string searchBase = "", DomainController domainController = null)
        {
            ldapFilter = string.Format("(&(objectCategory={0}){1})", "Group", ldapFilter);
            return LdapQueryOne(ldapFilter, attributes, searchBase, domainController);
        }

        public static List<SearchResult> GetGroups(string ldapFilter, string attributes = "", string searchBase = "", DomainController domainController = null)
        {
            ldapFilter = string.Format("(&(objectCategory={0}){1})", "Group", ldapFilter);
            return LdapQueryMany(ldapFilter, attributes, searchBase, domainController);
        }

        public static SearchResult GetUserOrGroup(string ldapFilter, string attributes = "", string searchBase = "", DomainController domainController = null)
        {
            ldapFilter = string.Format("(&(|(samAccountType={0})(objectCategory={1})){2})", 805306368, "Group", ldapFilter);
            return LdapQueryOne(ldapFilter, attributes, searchBase, domainController);
        }

        public static List<SearchResult> GetUsersOrGroups(string ldapFilter, string attributes = "", string searchBase = "", DomainController domainController = null)
        {
            ldapFilter = string.Format("(&(|(samAccountType={0})(objectCategory={1})){2})", 805306368, "Group", ldapFilter);
            return LdapQueryMany(ldapFilter, attributes, searchBase, domainController);
        }

        public static SearchResult GetComputer(string ldapFilter, string attributes = "", string searchBase = "", DomainController domainController = null)
        {
            ldapFilter = string.Format("(&(samAccountType=805306369)(!primaryGroupID=521)(!primaryGroupID=516)(!operatingSystem={0}){1})", "Windows*Server*", ldapFilter);
            return LdapQueryOne(ldapFilter, attributes, searchBase, domainController);
        }

        public static List<SearchResult> GetComputers(string ldapFilter, string attributes = "", string searchBase = "", DomainController domainController = null)
        {
            ldapFilter = string.Format("(&(samAccountType=805306369)(!primaryGroupID=521)(!primaryGroupID=516)(!operatingSystem={0}){1})", "Windows*Server*", ldapFilter);
            return LdapQueryMany(ldapFilter, attributes, searchBase, domainController);
        }

        public static SearchResult GetServer(string ldapFilter, string attributes = "", string searchBase = "", DomainController domainController = null)
        {
            ldapFilter = string.Format("(&(samAccountType={0})(operatingSystem={1}){2})", 805306369, "Windows*Server*", ldapFilter);
            return LdapQueryOne(ldapFilter, attributes, searchBase, domainController);
        }

        public static List<SearchResult> GetServers(string ldapFilter, string attributes = "", string searchBase = "", DomainController domainController = null)
        {
            ldapFilter = string.Format("(&(samAccountType={0})(operatingSystem={1}){2})", 805306369, "Windows*Server*", ldapFilter);
            return LdapQueryMany(ldapFilter, attributes, searchBase, domainController);
        }

        public static SearchResult GetDc(string ldapFilter, string attributes = "", string searchBase = "", DomainController domainController = null)
        {
            ldapFilter = string.Format("(&(samAccountType=805306369)(|(primaryGroupID=521)(primaryGroupID=516)){0})", ldapFilter);
            return LdapQueryOne(ldapFilter, attributes, searchBase, domainController);
        }

        public static List<SearchResult> GetDcs(string ldapFilter, string attributes = "", string searchBase = "", DomainController domainController = null)
        {
            ldapFilter = string.Format("(&(samAccountType=805306369)(|(primaryGroupID=521)(primaryGroupID=516)){0})", ldapFilter);
            return LdapQueryMany(ldapFilter, attributes, searchBase, domainController);
        }

        public static SearchResult GetRodc(string ldapFilter, string attributes = "", string searchBase = "", DomainController domainController = null)
        {
            ldapFilter = string.Format("(&(samAccountType=805306369)(|(primaryGroupID=521)){0})", ldapFilter);
            return LdapQueryOne(ldapFilter, attributes, searchBase, domainController);
        }

        public static List<SearchResult> GetRodcs(string ldapFilter, string attributes = "", string searchBase = "", DomainController domainController = null)
        {
            ldapFilter = string.Format("(&(samAccountType=805306369)(|(primaryGroupID=521)){0})", ldapFilter);
            return LdapQueryMany(ldapFilter, attributes, searchBase, domainController);
        }

        public static SearchResult GetRwdc(string ldapFilter, string attributes = "", string searchBase = "", DomainController domainController = null)
        {
            ldapFilter = string.Format("(&(samAccountType=805306369)(|(primaryGroupID=516)){0})", ldapFilter);
            return LdapQueryOne(ldapFilter, attributes, searchBase, domainController);
        }

        public static List<SearchResult> GetRwdcs(string ldapFilter, string attributes = "", string searchBase = "", DomainController domainController = null)
        {
            ldapFilter = string.Format("(&(samAccountType=805306369)(|(primaryGroupID=516)){0})", ldapFilter);
            return LdapQueryMany(ldapFilter, attributes, searchBase, domainController);
        }

        public static List<SearchResult> GetMembership(SearchResult searchResult, string attributes = "", string searchBase = "", DomainController domainController = null)
        {
            attributes = AddAttributes(String.Format("{0},{1}", "primaryGroupID", attributes));
            List<SearchResult> groups = new List<SearchResult>();

            int pgi = GetValueOfSingleValuedAttr<int>(searchResult, "primaryGroupID");
            if (pgi > 0)
            {
                byte[] sidBytes = GetValueOfSingleValuedAttr<byte[]>(searchResult, "objectSid");
                SecurityIdentifier sidUser = new SecurityIdentifier(sidBytes, 0);
                string sidPrimGroupString = string.Format("{0}-{1}", sidUser.AccountDomainSid.ToString(), pgi);
                SecurityIdentifier sidPrimGroup = new SecurityIdentifier(sidPrimGroupString);

                SearchResult sr2 = LdapQueryOne(sidPrimGroup, attributes, domainController);
                groups.Add(sr2);
            };

            string ldapFilter = string.Format("(&(objectCategory={0})(member:1.2.840.113556.1.4.1941:={1}))", "Group", GetValueOfSingleValuedAttr<String>(searchResult, "distinguishedName"));
            List<SearchResult> items = LdapQueryMany(ldapFilter, attributes, searchBase, domainController);
            groups.AddRange(items);

            return groups;
        }

        public static List<string> GetUserMembershipSids(SearchResult searchResult, string attributes = "", string searchBase = "", DomainController domainController = null)
        {
            List<string> groupSids = new List<string>();
            List<SearchResult> groups = GetMembership(searchResult, attributes, searchBase, domainController);
            groups.ForEach(item => { groupSids.Add(GetObjectSid(item).ToString()); });
            return groupSids;
        }

        public static void SetUserPassword(SearchResult searchResult, string password, bool userMustChangePassword)
        {
            EnsureUser(searchResult);
            int uac = GetValueOfSingleValuedAttr<int>(searchResult, "userAccountControl");
            DirectoryEntry de = GetNewWritableDirectoryEntry(searchResult);
            de.Invoke("SetPassword", new object[] { password });
            de.Properties["lockoutTime"].Value = 0;

            if (userMustChangePassword == true)
            {

                //	Forcing user to change his password at first logon is possible ONLY when:
                //	[1] User can change his password (ACL doesn't contain DENY entries for pwd change for Everyone & Self)
                //	[2] User's password doesn't expire (DONT_EXPIRE_PASSWORD is not set)
                //	[3] pwdLastSet is set to 0

                //  ADS_UF_DONT_EXPIRE_PASSWD
                de.Properties["userAccountControl"].Value = uac & ~Globals.ADS_UF_DONT_EXPIRE_PASSWD;
                //  ADS_UF_PASSWD_CANT_CHANGE
                de.Properties["userAccountControl"].Value = uac & ~Globals.ADS_UF_PASSWD_CANT_CHANGE;
                de.Properties["pwdLastSet"].Value = 0;

                //  http://devblog.rayonnant.net/2011/04/ad-net-toggle-users-cant-change.html
                SecurityIdentifier everyoneSid = new SecurityIdentifier(WellKnownSidType.WorldSid, null);
                SecurityIdentifier selfSid = new SecurityIdentifier(WellKnownSidType.SelfSid, null);
                Guid changePasswordGuid = new Guid("{AB721A53-1E2F-11D0-9819-00AA0040529B}");
                ActiveDirectoryAccessRule allowEveryone = new ActiveDirectoryAccessRule(everyoneSid, ActiveDirectoryRights.ExtendedRight, AccessControlType.Allow, changePasswordGuid);
                ActiveDirectoryAccessRule allowSelf = new ActiveDirectoryAccessRule(selfSid, ActiveDirectoryRights.ExtendedRight, AccessControlType.Allow, changePasswordGuid);
                ActiveDirectoryAccessRule denyEveryone = new ActiveDirectoryAccessRule(everyoneSid, ActiveDirectoryRights.ExtendedRight, AccessControlType.Deny, changePasswordGuid);
                ActiveDirectoryAccessRule denySelf = new ActiveDirectoryAccessRule(selfSid, ActiveDirectoryRights.ExtendedRight, AccessControlType.Deny, changePasswordGuid);

                ActiveDirectorySecurity userSecurity = de.ObjectSecurity;
                userSecurity.RemoveAccessRuleSpecific(denyEveryone);
                userSecurity.AddAccessRule(allowEveryone);
                userSecurity.RemoveAccessRuleSpecific(denySelf);
                userSecurity.AddAccessRule(allowSelf);

            }
            de.CommitChanges();
            de.Close();
        }

        public static void UnlockUserAccount(SearchResult searchResult, string searchBase = "", DomainController domainController = null)
        {
            EnsureUser(searchResult);
            int uac = GetValueOfSingleValuedAttr<int>(searchResult, "userAccountControl");
            DirectoryEntry de = GetNewWritableDirectoryEntry(searchResult);
            de.Properties["lockoutTime"].Value = 0;
            de.CommitChanges();
            de.Close();
        }

        public static void CheckWritableDomainController(DomainController domainController)
        {
            if (!IsWritableDomainController(domainController))
            {
                throw new Exception(string.Format("{0} is not writable domain controller!", domainController.Name));
            }
        }

        public static bool IsWritableDomainController(DomainController domainController)
        {
            LdapObject lo = LdapObject.GetComputer("dnsHostName", domainController.Name, "PrimaryGroupId");
            int primGroup = lo.SingleValue<int>("PrimaryGroupId");
            if (primGroup != 516)
                return false;
            else
                return true;
        }

        public static void EnableAccount(SearchResult searchResult, DomainController domainController = null)
        {
            EnsureAccount(searchResult);
            int uac = GetValueOfSingleValuedAttr<int>(searchResult, "userAccountControl");
            DirectoryEntry de = GetNewWritableDirectoryEntry(searchResult);
            de.Properties["userAccountControl"].Value = uac & ~2;
            de.CommitChanges();
            de.Close();
        }

        public static void DisableAccount(SearchResult searchResult, DomainController domainController = null)
        {
            EnsureAccount(searchResult);
            int uac = GetValueOfSingleValuedAttr<int>(searchResult, "userAccountControl");
            DirectoryEntry de = GetNewWritableDirectoryEntry(searchResult);
            de.Properties["userAccountControl"].Value = uac | 2;
            de.CommitChanges();
            de.Close();
        }

        public static string GetAdsPathGuid(SearchResult searchResult, DomainController domainController = null)
        {
            domainController = GetDomainController(domainController);
            return string.Format("LDAP://{0}/<GUID={1}>", domainController.Name, GetObjectGuid(searchResult));
        }

        public static string GetWritableAdsPathGuid(SearchResult searchResult, DomainController domainController = null)
        {
            domainController = GetWritableDomainController(domainController);
            return string.Format("LDAP://{0}/<GUID={1}>", domainController.Name, GetObjectGuid(searchResult));
        }

        public static string GetAdsPath(SearchResult searchResult, DomainController domainController = null)
        {
            domainController = GetDomainController(domainController);
            return string.Format("LDAP://{0}/{1}", domainController.Name, GetValueOfSingleValuedAttr<String>(searchResult, "distinguishedName"));
        }

        public static string GetWritableAdsPath(SearchResult searchResult, DomainController domainController = null)
        {
            domainController = GetWritableDomainController(domainController);
            return string.Format("LDAP://{0}/{1}", domainController.Name, GetValueOfSingleValuedAttr<String>(searchResult, "distinguishedName"));
        }

        public static DirectoryEntry GetNewDirectoryEntry(SearchResult searchResult, String username = null, String password = null, DomainController domainController = null)
        {
            return new DirectoryEntry(GetAdsPathGuid(searchResult, domainController), username, password);
        }

        public static DirectoryEntry GetNewWritableDirectoryEntry(SearchResult searchResult, String username = null, String password = null, DomainController domainController = null)
        {
            domainController = GetWritableDomainController(domainController);
            string adsPath = string.Format("LDAP://{0}/<GUID={1}>", domainController.Name, GetObjectGuid(searchResult));
            return new DirectoryEntry(adsPath, username, password);
        }

        public static void EnsureSamAccountTypes(SearchResult searchResult, params int[] samAccountTypes)
        {
            int sat = GetValueOfSingleValuedAttr<int>(searchResult, "samAccoutType");
            foreach (int k in samAccountTypes)
                if (sat != k)
                    throw new Exception(String.Format("Invalid SamAccountType value for [{0}]! Expected: {1}, found: {2}", GetValueOfSingleValuedAttr<String>(searchResult, "distinguishedName"), String.Join<int>("|", samAccountTypes), sat));
        }

        public static void EnsureAccount(SearchResult searchResult)
        {
            EnsureSamAccountTypes(searchResult, Globals.SAM_MACHINE_ACCOUNT, Globals.SAM_USER_OBJECT);
        }

        public static void EnsureUser(SearchResult searchResult)
        {
            EnsureSamAccountTypes(searchResult, Globals.SAM_USER_OBJECT);
        }

        public static void EnsureGroup(SearchResult searchResult)
        {
            EnsureSamAccountTypes(searchResult, Globals.SAM_ALIAS_OBJECT, Globals.SAM_GROUP_OBJECT, Globals.SAM_NON_SECURITY_ALIAS_OBJECT, Globals.SAM_NON_SECURITY_GROUP_OBJECT);
        }

        public static void EnsureAccountOrGroup(SearchResult searchResult)
        {
            EnsureAccount(searchResult);
            EnsureGroup(searchResult);
        }

        public static void EnsureUserOrGroup(SearchResult searchResult)
        {
            EnsureUser(searchResult);
            EnsureGroup(searchResult);
        }

        public static string UacToText(int userAccountControl, Int64 lockoutTime)
        {

            if (lockoutTime == 0)
                if ((userAccountControl & 2) != 2)
                    if (userAccountControl != 0)
                        return "E";
                    else
                        return null;
                else
                    return "D";
            else
                return "L";
        }

        public static string GetGroupTypeText(Int64 groupType)
        {
            string groupTypeText = "?";
            string groupScope = "?";

            if ((groupType & 0x80000000) == 0x80000000)
                groupTypeText = "Security";
            else
                groupTypeText = "Distribution";


            return groupTypeText;
        }

        public static string GetGroupScopeText(Int64 groupType, int samAccountType)
        {
            string groupScopeText = "?";
            if ((groupType & 0x00000008) == 0x00000008)
                groupScopeText = "Universal";
            else
                if ((samAccountType & 0x10000001) == 0x10000001 || (samAccountType & 0x10000000) == 0x10000000)
                    groupScopeText = "Global";
                else
                    if ((samAccountType & 0x20000001) == 0x20000001 || (samAccountType & 0x20000000) == 0x20000000)
                        groupScopeText = "DomainLocal";

            return groupScopeText;
        }

    }
}
