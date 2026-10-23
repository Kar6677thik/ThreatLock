using Microsoft.EntityFrameworkCore;
using Npgsql;

namespace ThreatLock.Infrastructure.Persistence;

public static class DbExceptions
{
    /// <summary>
    /// True when PostgreSQL rejected a write because of a unique index (SQLSTATE 23505).
    /// "Check first, then insert" leaves a race window; the unique index is the real guarantee,
    /// and this lets callers turn the violation into a clean 409 instead of a 500.
    /// </summary>
    public static bool IsUniqueViolation(this DbUpdateException exception) =>
        exception.InnerException is PostgresException { SqlState: PostgresErrorCodes.UniqueViolation };
}
