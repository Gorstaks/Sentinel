using System;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32;
using Sentinel.Core;
using Xunit;

namespace Sentinel.Tests
{
    public class Release346WindowsTests
    {
        [EndpointWindowsAdminFact]
        public void ProtectedProviderCredentialRoundTripsAndRejectsUnprivilegedReadAccess()
        {
            string path = @"Software\Sentinel346Credential_" + Guid.NewGuid().ToString("N");
            using var user = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Registry64);
            try
            {
                using var key = user.CreateSubKey(path)!;
                var acl = new RegistrySecurity();
                acl.SetAccessRuleProtection(true, false);
                var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
                acl.SetOwner(admins);
                foreach (var sid in new[] { admins, new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null) })
                    acl.AddAccessRule(new RegistryAccessRule(sid, RegistryRights.FullControl,
                        InheritanceFlags.ContainerInherit, PropagationFlags.None, AccessControlType.Allow));
                key.SetAccessControl(acl);
                var encrypted = ProtectedData.Protect(Encoding.UTF8.GetBytes("inert-fixture-key"), null, DataProtectionScope.LocalMachine);
                key.SetValue("MalwareBazaarAuthKey", encrypted, RegistryValueKind.Binary);
                Assert.Equal("inert-fixture-key", MalwareBazaarCredential.ReadProtectedKey(key));
                acl.AddAccessRule(new RegistryAccessRule(new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null),
                    RegistryRights.ReadKey, AccessControlType.Allow));
                key.SetAccessControl(acl);
                Assert.Throws<UnauthorizedAccessException>(() => MalwareBazaarCredential.ReadProtectedKey(key));
            }
            finally { user.DeleteSubKeyTree(path, false); }
        }
    }
}
