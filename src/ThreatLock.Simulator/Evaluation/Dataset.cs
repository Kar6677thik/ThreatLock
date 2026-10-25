using System.Text.Json.Nodes;
using ThreatLock.Core.Detection;
using ThreatLock.Core.Events;
using ThreatLock.Core.Geo;

namespace ThreatLock.Simulator.Evaluation;

public enum Label { Benign, Malicious }

/// <summary>The scenario kinds of SPEC §16.1, each with its label and what we expect to happen.</summary>
public static class ScenarioKinds
{
    // Benign
    public const string Office = "office_worker";
    public const string Traveller = "traveller";
    public const string Vpn = "corporate_vpn";
    public const string Mobile = "mobile_user";
    public const string PowerUser = "power_user";
    public const string NewLaptop = "new_laptop";
    public const string NewLaptopExport = "new_laptop_export";   // the honest, expected false positive

    // Malicious
    public const string TorLogin = "tor_login";
    public const string StolenSession = "stolen_session_replay";
    public const string Scraper = "scraper";
    public const string NewDeviceExport = "new_device_export";
    public const string RefreshReuse = "refresh_token_reuse";

    public static IReadOnlyList<string> Benign { get; } = [Office, Traveller, Vpn, Mobile, PowerUser, NewLaptop, NewLaptopExport];
    public static IReadOnlyList<string> Malicious { get; } = [TorLogin, StolenSession, Scraper, NewDeviceExport, RefreshReuse];

    /// <summary>Which detectors count as "caught it" for a malicious kind (SPEC §16.1).</summary>
    public static IReadOnlyList<string> Expected(string kind) => kind switch
    {
        TorLogin => [DetectorIds.Tor],
        StolenSession => [DetectorIds.ImpossibleTravel, DetectorIds.SessionHijack],
        Scraper => [DetectorIds.Scraping],
        NewDeviceExport => [DetectorIds.NewDeviceExport],
        RefreshReuse => [DetectorIds.SessionHijack],
        _ => [],
    };
}

/// <summary>
/// One labelled scenario instance: one user's activity over the scenario's duration. That's the
/// unit the false-positive rate and recall count (SPEC §16.1).
/// </summary>
public sealed record Scenario(int Index, string Kind, Label Label, Guid OrgId, Guid UserId, IReadOnlyList<ActivityEvent> Events);

/// <summary>Places, with the synthetic address ranges the generator uses for them.</summary>
public static class Places
{
    // 198.18.0.0/15 is reserved for benchmarking (RFC 2544): never a real client.
    public static readonly (string Prefix, GeoInfo Geo) Bengaluru = ("198.18.1.", new("IN", "Bengaluru", 12.9716, 77.5946, 50));
    public static readonly (string Prefix, GeoInfo Geo) Chennai = ("198.18.2.", new("IN", "Chennai", 13.0827, 80.2707, 50));
    public static readonly (string Prefix, GeoInfo Geo) Hyderabad = ("198.18.3.", new("IN", "Hyderabad", 17.3850, 78.4867, 50));
    public static readonly (string Prefix, GeoInfo Geo) London = ("198.18.4.", new("GB", "London", 51.5074, -0.1278, 50));
    public static readonly (string Prefix, GeoInfo Geo) NewYork = ("198.18.5.", new("US", "New York", 40.7128, -74.0060, 50));
    public static readonly (string Prefix, GeoInfo Geo) SaoPaulo = ("198.18.6.", new("BR", "São Paulo", -23.5505, -46.6333, 50));
    public static readonly (string Prefix, GeoInfo Geo) VpnBengaluru = ("198.19.10.", new("IN", "Bengaluru", 12.9716, 77.5946, 50));
    public static readonly (string Prefix, GeoInfo Geo) VpnFrankfurt = ("198.19.20.", new("DE", "Frankfurt", 50.1109, 8.6821, 50));
    public static readonly (string Prefix, GeoInfo Geo) Tor = ("198.19.200.", new("NL", "Amsterdam", 52.3676, 4.9041, 50));

    /// <summary>The corporate VPN's egress networks, which the evaluated org has put in <c>trustedNetworks</c>.</summary>
    public static readonly string[] VpnNetworks = ["198.19.10.0/24", "198.19.20.0/24"];

    /// <summary>The Tor exits the replay's static exit list contains.</summary>
    public static IEnumerable<string> TorExits() => Enumerable.Range(1, 254).Select(i => $"{Tor.Prefix}{i}");
}

/// <summary>
/// Generates the labelled dataset (SPEC §16.1, ADR-0006). Everything comes from one seeded
/// <see cref="Random"/> (ids, times, addresses), so a seed always produces the same dataset and
/// "before vs after" comparisons run on identical traffic. Scenarios are produced one at a time:
/// the full dataset is millions of events.
/// </summary>
public sealed class DatasetGenerator(int seed)
{
    public const string Chrome = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36";
    public const string Firefox = "Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0";
    public const string Curl = "curl/8.15.0";

    /// <summary>A Monday, 03:30 UTC = 09:00 in India.</summary>
    public static readonly DateTimeOffset Start = new(2026, 9, 7, 3, 30, 0, TimeSpan.Zero);

    private readonly Random random = new(seed);

    public static Guid OrgId { get; } = Guid.Parse("0199f2a0-0000-7000-8000-00000000e7a1");

    public IEnumerable<Scenario> Generate(int benign, int malicious)
    {
        var index = 0;
        for (var i = 0; i < benign; i++) yield return Build(index++, ScenarioKinds.Benign[i % ScenarioKinds.Benign.Count], Label.Benign);
        for (var i = 0; i < malicious; i++) yield return Build(index++, ScenarioKinds.Malicious[i % ScenarioKinds.Malicious.Count], Label.Malicious);
    }

    private Scenario Build(int index, string kind, Label label)
    {
        var user = NewGuid();
        var b = new Builder(this, user);
        switch (kind)
        {
            case ScenarioKinds.Office: Office(b, days: 10); break;
            case ScenarioKinds.Traveller: Traveller(b); break;
            case ScenarioKinds.Vpn: Vpn(b); break;
            case ScenarioKinds.Mobile: Mobile(b); break;
            case ScenarioKinds.PowerUser: PowerUser(b); break;
            case ScenarioKinds.NewLaptop: NewLaptop(b, export: false); break;
            case ScenarioKinds.NewLaptopExport: NewLaptop(b, export: true); break;
            case ScenarioKinds.TorLogin: TorLogin(b); break;
            case ScenarioKinds.StolenSession: StolenSession(b); break;
            case ScenarioKinds.Scraper: Scraper(b); break;
            case ScenarioKinds.NewDeviceExport: AttackerNewDevice(b); break;
            case ScenarioKinds.RefreshReuse: RefreshReuse(b); break;
            default: throw new ArgumentOutOfRangeException(nameof(kind), kind, "Unknown scenario kind.");
        }

        return new Scenario(index, kind, label, OrgId, user, b.Events);
    }

    // ---------- benign ----------

    /// <summary>A normal working day: sign in from the office, read a few dozen notes over eight hours.</summary>
    private void Workday(Builder b, DateTimeOffset day, (string Prefix, GeoInfo Geo) place, string device, int reads)
    {
        var session = b.Login(day.AddMinutes(random.Next(0, 60)), place, device, Chrome);
        for (var i = 0; i < reads; i++)
        {
            var at = day.AddMinutes(random.Next(60, 8 * 60));
            b.Read(session, at, place, device, Chrome, list: random.NextDouble() < 0.2);
        }
    }

    private void Office(Builder b, int days)
    {
        var device = b.Device();
        foreach (var day in Workdays(days)) Workday(b, day, Places.Bengaluru, device, random.Next(20, 61));
    }

    /// <summary>A week in Bengaluru, then a flight: London, 11 hours after the last activity.</summary>
    private void Traveller(Builder b)
    {
        var device = b.Device();
        var days = Workdays(5).ToList();
        foreach (var day in days) Workday(b, day, Places.Bengaluru, device, random.Next(20, 41));
        var lastActivity = b.Events.Max(e => e.OccurredAt);
        var landed = lastActivity.AddHours(11 + random.NextDouble() * 2);
        var session = b.Login(landed, Places.London, device, Chrome);
        for (var i = 0; i < 20; i++) b.Read(session, landed.AddMinutes(5 + i * random.Next(1, 10)), Places.London, device, Chrome);
    }

    /// <summary>The corporate VPN flips between exits in Bengaluru and Frankfurt (Break B3); the org trusts both.</summary>
    private void Vpn(Builder b)
    {
        var device = b.Device();
        foreach (var day in Workdays(5))
        {
            var exit = random.Next(2) == 0 ? Places.VpnBengaluru : Places.VpnFrankfurt;
            var session = b.Login(day.AddMinutes(random.Next(0, 30)), exit, device, Chrome);
            var at = day.AddMinutes(30);
            for (var i = 0; i < 30; i++)
            {
                if (random.NextDouble() < 0.3) exit = exit == Places.VpnBengaluru ? Places.VpnFrankfurt : Places.VpnBengaluru;
                b.Read(session, at, exit, device, Chrome);
                at = at.AddMinutes(random.Next(2, 16));
            }
        }
    }

    /// <summary>A phone: the carrier hands out a new address every few minutes, geolocated around south India.</summary>
    private void Mobile(Builder b)
    {
        var device = b.Device();
        (string, GeoInfo)[] cells = [Places.Bengaluru, Places.Chennai, Places.Hyderabad];
        foreach (var day in Workdays(3))
        {
            var cell = cells[random.Next(cells.Length)];
            var session = b.Login(day, cell, device, Chrome);
            var at = day;
            for (var i = 0; i < 40; i++)
            {
                at = at.AddMinutes(random.Next(2, 8));
                if (random.NextDouble() < 0.5) cell = cells[random.Next(cells.Length)];
                b.Read(session, at, cell, device, Chrome);
            }
        }
    }

    /// <summary>
    /// Reads a lot every day: a 30–45 minute burst at 30–70 reads a minute (normally distributed
    /// around 50), for two weeks. The baseline should learn this; whether it does before the first
    /// burst trips the cold-start floor is exactly what the evaluation measures.
    /// </summary>
    private void PowerUser(Builder b)
    {
        var device = b.Device();
        foreach (var day in Workdays(10))
        {
            var session = b.Login(day, Places.Bengaluru, device, Chrome);
            var burstStart = day.AddMinutes(random.Next(30, 240));
            var minutes = random.Next(30, 46);
            for (var m = 0; m < minutes; m++)
            {
                var perMinute = Math.Clamp((int)Math.Round(Normal(50, 8)), 30, 70);
                for (var r = 0; r < perMinute; r++)
                {
                    b.Read(session, burstStart.AddMinutes(m).AddSeconds(60.0 * r / perMinute), Places.Bengaluru, device, Chrome);
                }
            }
        }
    }

    /// <summary>A week on the old laptop, then a new one. With <paramref name="export"/>: a legitimate migration that exports 5 minutes in.</summary>
    private void NewLaptop(Builder b, bool export)
    {
        var old = b.Device();
        var days = Workdays(6).ToList();
        foreach (var day in days.Take(5)) Workday(b, day, Places.Bengaluru, old, random.Next(20, 41));

        var laptop = b.Device();
        var first = days[5].AddMinutes(random.Next(0, 60));
        var session = b.Login(first, Places.Bengaluru, laptop, Chrome);
        if (export) b.Export(session, first.AddMinutes(5), Places.Bengaluru, laptop, Chrome);
        for (var i = 0; i < 30; i++) b.Read(session, first.AddMinutes(10 + i * random.Next(2, 10)), Places.Bengaluru, laptop, Chrome);
    }

    // ---------- malicious ----------

    private void TorLogin(Builder b)
    {
        Office(b, days: 3);
        var at = b.Events.Max(e => e.OccurredAt).AddHours(random.Next(1, 12));
        var device = b.Device();
        var session = b.Login(at, Places.Tor, device, Firefox);
        for (var i = 0; i < 10; i++) b.Read(session, at.AddMinutes(i + 1), Places.Tor, device, Firefox);
    }

    /// <summary>The victim's live session token is replayed from another continent, minutes later, on the thief's machine.</summary>
    private void StolenSession(Builder b)
    {
        var device = b.Device();
        var day = Workdays(1).Single();
        var session = b.Login(day, Places.Bengaluru, device, Chrome);
        for (var i = 0; i < 10; i++) b.Read(session, day.AddMinutes(5 + i), Places.Bengaluru, device, Chrome);

        var thiefAt = day.AddMinutes(20 + random.Next(0, 40));
        (string, GeoInfo)[] elsewhere = [Places.London, Places.NewYork, Places.SaoPaulo];
        var where = elsewhere[random.Next(elsewhere.Length)];
        var thief = $"thief-{random.Next():x}";
        for (var i = 0; i < 10; i++) b.Read(session, thiefAt.AddSeconds(i * 20), where, thief, Curl);
    }

    /// <summary>Someone with the user's session pulls notes at ~300 a minute for three minutes.</summary>
    private void Scraper(Builder b)
    {
        Office(b, days: 2);
        var device = b.Events.First(e => e.DeviceId is not null).DeviceId!;
        var at = b.Events.Max(e => e.OccurredAt).AddMinutes(30);
        var session = b.Login(at, Places.Bengaluru, device, Chrome);
        var perMinute = random.Next(250, 351);
        for (var r = 0; r < perMinute * 3; r++) b.Read(session, at.AddMinutes(1).AddSeconds(60.0 * r / perMinute), Places.Bengaluru, device, Chrome);
    }

    /// <summary>Stolen password: a login on a never-seen device from the same country, and an export two minutes later.</summary>
    private void AttackerNewDevice(Builder b)
    {
        Office(b, days: 3);
        var at = b.Events.Max(e => e.OccurredAt).AddHours(random.Next(1, 6));
        var device = b.Device();
        var session = b.Login(at, Places.Chennai, device, Firefox);
        b.Export(session, at.AddMinutes(2), Places.Chennai, device, Firefox);
    }

    /// <summary>Two parties hold one refresh token; the second refresh is detected as reuse (SPEC §6.4).</summary>
    private void RefreshReuse(Builder b)
    {
        var device = b.Device();
        var day = Workdays(1).Single();
        var session = b.Login(day, Places.Bengaluru, device, Chrome);
        b.Read(session, day.AddMinutes(3), Places.Bengaluru, device, Chrome);
        b.Add(EventTypes.TokenRefreshed, session, day.AddMinutes(10), Places.Bengaluru, device, Chrome);
        b.Add(EventTypes.RefreshTokenReused, session, day.AddMinutes(10 + random.Next(1, 120)), Places.London, $"thief-{random.Next():x}", Curl);
    }

    // ---------- helpers ----------

    private IEnumerable<DateTimeOffset> Workdays(int count)
    {
        var offset = random.Next(0, 5);   // users don't all start on the same day
        var day = Start.AddDays(offset);
        for (var produced = 0; produced < count; day = day.AddDays(1))
        {
            if (day.DayOfWeek is DayOfWeek.Saturday or DayOfWeek.Sunday) continue;
            produced++;
            yield return day;
        }
    }

    private double Normal(double mean, double std)
    {
        // Box–Muller: two uniform numbers make one normally distributed one.
        var u1 = 1.0 - random.NextDouble();
        var u2 = random.NextDouble();
        return mean + std * Math.Sqrt(-2.0 * Math.Log(u1)) * Math.Cos(2.0 * Math.PI * u2);
    }

    private Guid NewGuid()
    {
        Span<byte> bytes = stackalloc byte[16];
        random.NextBytes(bytes);
        return new Guid(bytes);
    }

    /// <summary>Accumulates one scenario's events, and plays the API's part in what it records (session ids, <c>newDevice</c>).</summary>
    private sealed class Builder(DatasetGenerator generator, Guid user)
    {
        private readonly HashSet<string> devicesSeen = [];
        private int devices;

        public List<ActivityEvent> Events { get; } = [];

        public string Device() => $"dev-{user.ToString("N")[..8]}-{++devices}";

        public Guid Login(DateTimeOffset at, (string Prefix, GeoInfo Geo) place, string device, string agent)
        {
            var session = generator.NewGuid();
            // As SessionService decides: new for a user who already has other devices.
            var isNew = !devicesSeen.Contains(device) && devicesSeen.Count > 0;
            devicesSeen.Add(device);
            Add(EventTypes.LoginSucceeded, session, at, place, device, agent,
                new JsonObject { [NewDeviceExportDetector.NewDeviceMetadata] = isNew });
            return session;
        }

        public void Read(Guid session, DateTimeOffset at, (string Prefix, GeoInfo Geo) place, string device, string agent, bool list = false) =>
            Add(list ? EventTypes.NoteListed : EventTypes.NoteRead, session, at, place, device, agent,
                list ? null : new JsonObject { ["noteId"] = $"note-{generator.random.Next(0, 200)}" });

        public void Export(Guid session, DateTimeOffset at, (string Prefix, GeoInfo Geo) place, string device, string agent) =>
            Add(EventTypes.ExportRequested, session, at, place, device, agent, new JsonObject { ["noteCount"] = generator.random.Next(20, 200) });

        public void Add(string type, Guid session, DateTimeOffset at, (string Prefix, GeoInfo Geo) place, string device, string agent, JsonObject? metadata = null) =>
            Events.Add(new ActivityEvent(generator.NewGuid(), OrgId, user, session, type, at, $"{place.Prefix}{generator.random.Next(1, 255)}",
                place.Geo, device, agent, null, metadata));
    }
}
