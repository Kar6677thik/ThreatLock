using Microsoft.EntityFrameworkCore;
using Npgsql;

namespace ThreatLock.Infrastructure.Persistence;

/// <summary>One place that says how the DbContext talks to PostgreSQL, shared by runtime and tools.</summary>
public static class DbContextConfiguration
{
    public static void Configure(DbContextOptionsBuilder options, NpgsqlDataSource dataSource) =>
        Apply(options.UseNpgsql(dataSource, Npgsql));

    public static void Configure(DbContextOptionsBuilder options, string connectionString) =>
        Apply(options.UseNpgsql(connectionString, Npgsql));

    private static void Npgsql(Npgsql.EntityFrameworkCore.PostgreSQL.Infrastructure.NpgsqlDbContextOptionsBuilder npgsql) =>
        npgsql.MigrationsHistoryTable("__ef_migrations_history");

    // snake_case tables and columns (asp_net_users, created_at): the PostgreSQL convention,
    // and it means hand-written SQL later (job queue, audit chain) needs no quoting.
    private static void Apply(DbContextOptionsBuilder options) => options.UseSnakeCaseNamingConvention();
}
