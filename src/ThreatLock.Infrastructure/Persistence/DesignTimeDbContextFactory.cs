using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace ThreatLock.Infrastructure.Persistence;

/// <summary>
/// Used only by the <c>dotnet ef</c> tool (creating migrations), never at runtime. Lets the tool
/// build the model without starting the API. The connection string is irrelevant for
/// <c>migrations add</c>; for <c>database update</c> set THREATLOCK_MIGRATIONS_CONNECTION.
/// </summary>
internal sealed class DesignTimeDbContextFactory : IDesignTimeDbContextFactory<ThreatLockDbContext>
{
    public ThreatLockDbContext CreateDbContext(string[] args)
    {
        var connection = Environment.GetEnvironmentVariable("THREATLOCK_MIGRATIONS_CONNECTION")
            ?? "Host=127.0.0.1;Port=5433;Database=threatlock;Username=threatlock;Password=threatlock-dev";

        var options = new DbContextOptionsBuilder<ThreatLockDbContext>();
        DbContextConfiguration.Configure(options, connection);
        return new ThreatLockDbContext(options.Options, new NoTenantContext());
    }
}
