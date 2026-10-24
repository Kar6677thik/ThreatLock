using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace ThreatLock.Infrastructure.Persistence;

public sealed class ThreatLockDbContext(DbContextOptions<ThreatLockDbContext> options, ITenantContext tenant)
    : IdentityDbContext<AppUser, AppRole, Guid>(options)
{
    public DbSet<Org> Orgs => Set<Org>();
    public DbSet<Note> Notes => Set<Note>();
    public DbSet<Session> Sessions => Set<Session>();
    public DbSet<RefreshToken> RefreshTokens => Set<RefreshToken>();
    public DbSet<ActivityEventRecord> ActivityEvents => Set<ActivityEventRecord>();
    public DbSet<Anomaly> Anomalies => Set<Anomaly>();
    public DbSet<TorExitSnapshot> TorExitSnapshots => Set<TorExitSnapshot>();

    /// <summary>
    /// Read by the query filter below. EF Core turns a reference to a DbContext member into a
    /// query parameter evaluated per query, so one compiled model serves every tenant.
    /// </summary>
    private Guid? CurrentOrgId => tenant.OrgId;

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);

        // Seed data becomes part of the migration. Ids and concurrency stamps must be constants,
        // or every `migrations add` would see a "change" and re-seed.
        builder.Entity<AppRole>().HasData(SeededRoles.All);

        builder.Entity<Org>(org =>
        {
            org.Property(o => o.Name).HasMaxLength(100);
            org.Property(o => o.Slug).HasMaxLength(50);
            org.HasIndex(o => o.Slug).IsUnique();
        });

        // Identity hard-codes table names like "AspNetUsers", which bypasses the snake_case
        // convention; rename them to match the rest of the schema (SPEC §12).
        builder.Entity<AppRole>().ToTable("roles");
        builder.Entity<IdentityUserRole<Guid>>().ToTable("user_roles");
        builder.Entity<IdentityUserClaim<Guid>>().ToTable("user_claims");
        builder.Entity<IdentityUserLogin<Guid>>().ToTable("user_logins");
        builder.Entity<IdentityUserToken<Guid>>().ToTable("user_tokens");
        builder.Entity<IdentityRoleClaim<Guid>>().ToTable("role_claims");

        builder.Entity<AppUser>(user =>
        {
            user.ToTable("users");
            user.Property(u => u.DisplayName).HasMaxLength(100);

            // Identity checks email uniqueness in code (RequireUniqueEmail), but two sign-ups
            // racing each other can both pass that check. Only the database can guarantee it.
            user.HasIndex(u => u.NormalizedEmail).IsUnique().HasDatabaseName("ix_users_normalized_email");
            user.HasOne(u => u.Org).WithMany().HasForeignKey(u => u.OrgId).OnDelete(DeleteBehavior.Restrict);
            user.HasIndex(u => u.OrgId);
        });

        builder.Entity<Note>(note =>
        {
            note.Property(n => n.Title).HasMaxLength(200);
            note.Property(n => n.Body).HasMaxLength(20_000);
            note.HasOne<Org>().WithMany().HasForeignKey(n => n.OrgId).OnDelete(DeleteBehavior.Restrict);
            note.HasOne<AppUser>().WithMany().HasForeignKey(n => n.OwnerId).OnDelete(DeleteBehavior.Cascade);
            note.HasIndex(n => new { n.OrgId, n.OwnerId });

            // Tenant isolation, enforced once for every query on notes (SPEC §4). With no tenant
            // (null) the comparison is never true, so a missing tenant fails *closed*.
            note.HasQueryFilter(n => n.OrgId == CurrentOrgId);
        });

        // Not tenant-filtered: the session check runs before we trust any tenant claim, and it
        // looks sessions up by their unguessable id. Queries by user filter by org explicitly.
        builder.Entity<Session>(session =>
        {
            session.Property(s => s.CreatedDeviceId).HasMaxLength(64);
            session.Property(s => s.CreatedUserAgent).HasMaxLength(512);
            session.Property(s => s.RevokedReason).HasMaxLength(50);
            session.HasOne<AppUser>().WithMany().HasForeignKey(s => s.UserId).OnDelete(DeleteBehavior.Cascade);
            session.HasOne<Org>().WithMany().HasForeignKey(s => s.OrgId).OnDelete(DeleteBehavior.Restrict);

            // "All live sessions of this user" is the revocation query; a partial index keeps it
            // small because revoked sessions (the vast majority over time) aren't in it.
            session.HasIndex(s => s.UserId).HasFilter("revoked_at IS NULL").HasDatabaseName("ix_sessions_user_id_active");
        });

        builder.Entity<RefreshToken>(token =>
        {
            token.Property(t => t.TokenHash).HasMaxLength(32);
            token.HasIndex(t => t.TokenHash).IsUnique();
            token.HasIndex(t => t.SessionId);
            token.HasOne<Session>().WithMany().HasForeignKey(t => t.SessionId).OnDelete(DeleteBehavior.Cascade);
        });

        // No foreign keys on events: they're high-volume telemetry, written on the hot path and
        // purged after 30 days. An FK check per insert buys little here.
        builder.Entity<ActivityEventRecord>(evt =>
        {
            evt.ToTable("activity_events");
            evt.Property(e => e.Id).ValueGeneratedNever();
            evt.Property(e => e.Type).HasMaxLength(40);
            evt.Property(e => e.Geo).HasColumnType("jsonb");
            evt.Property(e => e.Metadata).HasColumnType("jsonb");
            evt.Property(e => e.DeviceId).HasMaxLength(64);
            evt.Property(e => e.UserAgent).HasMaxLength(512);
            evt.Property(e => e.RequestId).HasMaxLength(100);
            // The sweeper's query ("unpublished events") only ever touches a handful of rows;
            // a partial index keeps it tiny however large the table grows.
            evt.HasIndex(e => e.OccurredAt, "unpublished").HasFilter("published_at IS NULL").HasDatabaseName("ix_activity_events_unpublished");
            evt.HasIndex(e => new { e.UserId, e.OccurredAt });
            // Two indexes on the same column need explicit names, or EF quietly merges them into one;
            // HasDatabaseName then stops the snake_case convention from renaming them.
            evt.HasIndex(e => e.OccurredAt, "retention").HasDatabaseName("ix_activity_events_occurred_at");   // retention purge
        });

        builder.Entity<Anomaly>(anomaly =>
        {
            anomaly.Property(a => a.Detector).HasMaxLength(40);
            anomaly.Property(a => a.Severity).HasMaxLength(10);
            anomaly.Property(a => a.DedupeKey).HasMaxLength(200);
            anomaly.Property(a => a.Evidence).HasColumnType("jsonb");
            anomaly.Property(a => a.Decision).HasMaxLength(20);
            anomaly.Property(a => a.DecisionReason).HasMaxLength(100);
            anomaly.HasOne<Org>().WithMany().HasForeignKey(a => a.OrgId).OnDelete(DeleteBehavior.Restrict);
            anomaly.HasIndex(a => new { a.OrgId, a.DedupeKey }).IsUnique();
            anomaly.HasIndex(a => new { a.OrgId, a.DetectedAt });
        });

        builder.Entity<TorExitSnapshot>(snapshot => snapshot.Property(s => s.Source).HasMaxLength(500));
    }
}
