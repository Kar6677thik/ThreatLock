using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace ThreatLock.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddAuditLog : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "audit_log",
                columns: table => new
                {
                    org_id = table.Column<Guid>(type: "uuid", nullable: false),
                    seq = table.Column<long>(type: "bigint", nullable: false),
                    occurred_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    actor_type = table.Column<string>(type: "character varying(10)", maxLength: 10, nullable: false),
                    actor_id = table.Column<Guid>(type: "uuid", nullable: true),
                    action = table.Column<string>(type: "character varying(60)", maxLength: 60, nullable: false),
                    target_type = table.Column<string>(type: "character varying(40)", maxLength: 40, nullable: true),
                    target_id = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: true),
                    anomaly_id = table.Column<Guid>(type: "uuid", nullable: true),
                    details = table.Column<string>(type: "jsonb", nullable: false),
                    idempotency_key = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: true),
                    prev_hash = table.Column<byte[]>(type: "bytea", maxLength: 32, nullable: false),
                    entry_hash = table.Column<byte[]>(type: "bytea", maxLength: 32, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_audit_log", x => new { x.org_id, x.seq });
                    table.ForeignKey(
                        name: "fk_audit_log_orgs_org_id",
                        column: x => x.org_id,
                        principalTable: "orgs",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateIndex(
                name: "ix_audit_log_idempotency_key",
                table: "audit_log",
                column: "idempotency_key",
                unique: true);

            // Hand-written. Append-only, enforced by the database for *every* role, including the
            // table's owner, which is what the app connects as until M10 splits the roles. Only
            // a superuser who disables the trigger can change a row, and the hash chain exists to
            // catch exactly that (SPEC §11.3, Break B5).
            migrationBuilder.Sql(
                """
                CREATE FUNCTION audit_log_append_only() RETURNS trigger LANGUAGE plpgsql AS $$
                BEGIN
                    RAISE EXCEPTION 'audit_log is append-only: % is not allowed', TG_OP
                        USING ERRCODE = 'insufficient_privilege';
                END
                $$;

                CREATE TRIGGER audit_log_no_update_or_delete
                    BEFORE UPDATE OR DELETE ON audit_log
                    FOR EACH ROW EXECUTE FUNCTION audit_log_append_only();

                CREATE TRIGGER audit_log_no_truncate
                    BEFORE TRUNCATE ON audit_log
                    FOR EACH STATEMENT EXECUTE FUNCTION audit_log_append_only();

                -- Least privilege for the application role, once it exists (M10, SPEC §19).
                DO $$
                BEGIN
                    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'threatlock_app') THEN
                        REVOKE UPDATE, DELETE, TRUNCATE ON audit_log FROM threatlock_app;
                        GRANT SELECT, INSERT ON audit_log TO threatlock_app;
                    END IF;
                END
                $$;
                """);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql(
                """
                DROP TRIGGER IF EXISTS audit_log_no_truncate ON audit_log;
                DROP TRIGGER IF EXISTS audit_log_no_update_or_delete ON audit_log;
                DROP FUNCTION IF EXISTS audit_log_append_only();
                """);

            migrationBuilder.DropTable(
                name: "audit_log");
        }
    }
}
