using System.Security.Cryptography;
using Lumen.Core.Abstractions;

namespace Lumen.App.Services;

/// <summary>
/// Protects quarantine keys with Windows DPAPI in the current-user scope. The keys are
/// therefore readable only by the same Windows account on this machine.
/// </summary>
public sealed class DpapiSecretProtector : ISecretProtector
{
    private const DataProtectionScope Scope = DataProtectionScope.CurrentUser;

    public byte[] Protect(byte[] plaintext, byte[] entropy) =>
        ProtectedData.Protect(plaintext, entropy, Scope);

    public byte[] Unprotect(byte[] protectedData, byte[] entropy) =>
        ProtectedData.Unprotect(protectedData, entropy, Scope);
}
