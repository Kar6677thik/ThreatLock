using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using Npgsql;
using ThreatLock.Infrastructure.Audit;
using ThreatLock.Infrastructure.Persistence;

namespace ThreatLock.Api.Audit;

public static class AuditExtensions
{
    /// <summary>
    /// Appends inside the DbContext's open transaction if there is one, so the entry commits with
    /// the change it describes (creating a user, changing roles). Otherwise it uses a transaction
    /// of its own, right after the change.
    /// <para>
    /// The second case has a gap: a crash between the change and the append loses the entry.
    /// That's accepted for single-statement actions like logout (the activity event and the
    /// session row still record them); everything that already runs in a transaction is audited
    /// inside it.
    /// </para>
    /// </summary>
    public static Task<AuditAppended> AppendAsync(this AuditLog audit, ThreatLockDbContext db, AuditRecord record, CancellationToken ct) =>
        db.Database.CurrentTransaction is { } transaction
            ? audit.AppendAsync((NpgsqlConnection)db.Database.GetDbConnection(), (NpgsqlTransaction)transaction.GetDbTransaction(), record, ct)
            : audit.AppendAsync(record, ct);
}
