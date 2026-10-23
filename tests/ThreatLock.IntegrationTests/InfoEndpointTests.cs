using System.Net.Http.Json;
using ThreatLock.IntegrationTests.Infrastructure;

namespace ThreatLock.IntegrationTests;

public class InfoEndpointTests(ContainersFixture containers)
{
    private sealed record InfoResponse(string Name, string Version, string Environment);

    [Fact]
    public async Task Info_reports_name_version_and_environment_without_authentication()
    {
        using var client = containers.Api.CreateClient();

        var info = await client.GetFromJsonAsync<InfoResponse>("/api/info", TestContext.Current.CancellationToken);

        Assert.NotNull(info);
        Assert.Equal("ThreatLock", info.Name);
        Assert.False(string.IsNullOrWhiteSpace(info.Version));
        Assert.Equal("Testing", info.Environment);
    }
}
