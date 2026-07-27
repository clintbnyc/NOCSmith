using System.Security.Cryptography;
using System.Text;

namespace UnifiMcp.Journal;

internal sealed record ClientJournalMigration(int Version, string Sql)
{
    public string Checksum =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(Sql))).ToLowerInvariant();
}
