using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace ThreatLock.Infrastructure.Persistence;

public sealed class ThreatLockDbContext(DbContextOptions<ThreatLockDbContext> options, ITenantContext tenant)
    : IdentityDbContext<AppUser, AppRole, Guid>(options)
{
    public DbSet<Org> Orgs => Set<Org>();
    public DbSet<Note> Notes => Set<Note>();

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
    }
}
