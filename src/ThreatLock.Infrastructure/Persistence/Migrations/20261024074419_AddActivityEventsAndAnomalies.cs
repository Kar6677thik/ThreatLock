using System;
using System.Collections.Generic;
using System.Net;
using Microsoft.EntityFrameworkCore.Migrations;
using Npgsql.EntityFrameworkCore.PostgreSQL.Metadata;

#nullable disable

namespace ThreatLock.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddActivityEventsAndAnomalies : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "activity_events",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    org_id = table.Column<Guid>(type: "uuid", nullable: false),
                    user_id = table.Column<Guid>(type: "uuid", nullable: true),
                    session_id = table.Column<Guid>(type: "uuid", nullable: true),
                    type = table.Column<string>(type: "character varying(40)", maxLength: 40, nullable: false),
                    occurred_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    ip = table.Column<IPAddress>(type: "inet", nullable: true),
                    geo = table.Column<string>(type: "jsonb", nullable: true),
                    device_id = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true),
                    user_agent = table.Column<string>(type: "character varying(512)", maxLength: 512, nullable: true),
                    request_id = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: true),
                    metadata = table.Column<string>(type: "jsonb", nullable: true),
                    published_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_activity_events", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "anomalies",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    org_id = table.Column<Guid>(type: "uuid", nullable: false),
                    user_id = table.Column<Guid>(type: "uuid", nullable: false),
                    session_id = table.Column<Guid>(type: "uuid", nullable: true),
                    detector = table.Column<string>(type: "character varying(40)", maxLength: 40, nullable: false),
                    severity = table.Column<string>(type: "character varying(10)", maxLength: 10, nullable: false),
                    dedupe_key = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    evidence = table.Column<string>(type: "jsonb", nullable: false),
                    event_ids = table.Column<List<Guid>>(type: "uuid[]", nullable: false),
                    detected_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    policy_version = table.Column<int>(type: "integer", nullable: true),
                    decision = table.Column<string>(type: "character varying(20)", maxLength: 20, nullable: true),
                    decision_reason = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_anomalies", x => x.id);
                    table.ForeignKey(
                        name: "fk_anomalies_orgs_org_id",
                        column: x => x.org_id,
                        principalTable: "orgs",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "tor_exit_snapshots",
                columns: table => new
                {
                    id = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    fetched_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    source = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: false),
                    ips = table.Column<IPAddress[]>(type: "inet[]", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_tor_exit_snapshots", x => x.id);
                });

            migrationBuilder.CreateIndex(
                name: "ix_activity_events_occurred_at",
                table: "activity_events",
                column: "occurred_at");

            migrationBuilder.CreateIndex(
                name: "ix_activity_events_unpublished",
                table: "activity_events",
                column: "occurred_at",
                filter: "published_at IS NULL");

            migrationBuilder.CreateIndex(
                name: "ix_activity_events_user_id_occurred_at",
                table: "activity_events",
                columns: new[] { "user_id", "occurred_at" });

            migrationBuilder.CreateIndex(
                name: "ix_anomalies_org_id_dedupe_key",
                table: "anomalies",
                columns: new[] { "org_id", "dedupe_key" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_anomalies_org_id_detected_at",
                table: "anomalies",
                columns: new[] { "org_id", "detected_at" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "activity_events");

            migrationBuilder.DropTable(
                name: "anomalies");

            migrationBuilder.DropTable(
                name: "tor_exit_snapshots");
        }
    }
}
