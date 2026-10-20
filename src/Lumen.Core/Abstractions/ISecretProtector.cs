namespace Lumen.Core.Abstractions;

/// <summary>
/// Protects small secrets at rest (quarantine encryption keys). The desktop app implements
/// this with Windows DPAPI in the current-user scope. Tests can supply a fake.
/// </summary>
public interface ISecretProtector
{
    byte[] Protect(byte[] plaintext, byte[] entropy);
    byte[] Unprotect(byte[] protectedData, byte[] entropy);
}
