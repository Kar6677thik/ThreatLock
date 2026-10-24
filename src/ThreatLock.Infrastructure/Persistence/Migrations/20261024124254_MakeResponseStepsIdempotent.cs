using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace ThreatLock.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class MakeResponseStepsIdempotent : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "ix_notifications_anomaly_id",
                table: "notifications");

            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "notified_at",
                table: "response_jobs",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "revoked_at",
                table: "response_jobs",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "count",
                table: "notifications",
                type: "integer",
                nullable: false,
                defaultValue: 1);

            migrationBuilder.AddColumn<Guid>(
                name: "last_anomaly_id",
                table: "notifications",
                type: "uuid",
                nullable: false,
                defaultValue: new Guid("00000000-0000-0000-0000-000000000000"));

            migrationBuilder.AddColumn<Guid>(
                name: "subject_user_id",
                table: "notifications",
                type: "uuid",
                nullable: false,
                defaultValue: new Guid("00000000-0000-0000-0000-000000000000"));

            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "updated_at",
                table: "notifications",
                type: "timestamp with time zone",
                nullable: false,
                defaultValue: new DateTimeOffset(new DateTime(1, 1, 1, 0, 0, 0, 0, DateTimeKind.Unspecified), new TimeSpan(0, 0, 0, 0, 0)));

            // Hand-written: rows the naive responder left behind need real values for the new
            // columns, and its duplicates must go, or the unique index below can't be created.
            migrationBuilder.Sql(
                """
                UPDATE notifications n
                SET count = 1, last_anomaly_id = n.anomaly_id, updated_at = n.created_at, subject_user_id = a.user_id
                FROM anomalies a
                WHERE a.id = n.anomaly_id;

                DELETE FROM notifications n
                USING notifications keep
                WHERE keep.anomaly_id = n.anomaly_id
                  AND keep.recipient_user_id = n.recipient_user_id
                  AND keep.id < n.id;
                """);

            migrationBuilder.CreateIndex(
                name: "ix_notifications_anomaly_id_recipient_user_id",
                table: "notifications",
                columns: new[] { "anomaly_id", "recipient_user_id" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_notifications_recipient_user_id_subject_user_id",
                table: "notifications",
                columns: new[] { "recipient_user_id", "subject_user_id" },
                filter: "read_at IS NULL");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "ix_notifications_anomaly_id_recipient_user_id",
                table: "notifications");

            migrationBuilder.DropIndex(
                name: "ix_notifications_recipient_user_id_subject_user_id",
                table: "notifications");

            migrationBuilder.DropColumn(
                name: "notified_at",
                table: "response_jobs");

            migrationBuilder.DropColumn(
                name: "revoked_at",
                table: "response_jobs");

            migrationBuilder.DropColumn(
                name: "count",
                table: "notifications");

            migrationBuilder.DropColumn(
                name: "last_anomaly_id",
                table: "notifications");

            migrationBuilder.DropColumn(
                name: "subject_user_id",
                table: "notifications");

            migrationBuilder.DropColumn(
                name: "updated_at",
                table: "notifications");

            migrationBuilder.CreateIndex(
                name: "ix_notifications_anomaly_id",
                table: "notifications",
                column: "anomaly_id");
        }
    }
}
