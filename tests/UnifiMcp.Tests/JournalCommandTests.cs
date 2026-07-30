using System.Net;
using Microsoft.Data.Sqlite;
using UnifiMcp.Api;
using UnifiMcp.Configuration;

namespace UnifiMcp.Tests;

public sealed class JournalCommandTests
{
    [Fact]
    public void Parses_bounded_collection_options()
    {
        var options = JournalCommand.Parse(new[]
        {
            "collect",
            "--site-id",
            "6cc5f1b8-cec7-4c50-9b92-805b73892756",
            "--history-hours",
            "72"
        });

        Assert.Equal(
            "6cc5f1b8-cec7-4c50-9b92-805b73892756",
            options.SiteId);
        Assert.Equal(72, options.HistoryHours);
    }

    [Theory]
    [InlineData()]
    [InlineData("unknown")]
    [InlineData("collect", "--site-id", "not-a-uuid")]
    [InlineData("collect", "--history-hours", "25")]
    [InlineData("collect", "--unknown")]
    public void Rejects_invalid_collection_arguments(params string[] args)
    {
        Assert.Throws<ConfigurationException>(() => JournalCommand.Parse(args));
    }

    [Theory]
    [InlineData("complete", JournalCommand.CompleteExitCode)]
    [InlineData("partial", JournalCommand.PartialExitCode)]
    [InlineData("failed", JournalCommand.FailedCollectionExitCode)]
    [InlineData(null, JournalCommand.ErrorExitCode)]
    public void Maps_collection_status_to_machine_exit_code(
        string? status,
        int expected)
    {
        Assert.Equal(expected, JournalCommand.ExitCodeForStatus(status));
    }

    [Fact]
    public void Handles_controller_failures_as_redacted_operational_errors()
    {
        var apiFailure = new UnifiApiException(HttpStatusCode.BadGateway, "controller unavailable");
        var transportFailure = new HttpRequestException("transport unavailable");
        var journalFailure = new SqliteException("database is locked", 5);

        Assert.True(JournalCommand.IsHandledFailure(apiFailure));
        Assert.True(JournalCommand.IsHandledFailure(transportFailure));
        Assert.True(JournalCommand.IsHandledFailure(journalFailure));
        Assert.Equal(JournalCommand.ErrorExitCode, JournalCommand.ExitCodeForException(apiFailure));
        Assert.Equal(JournalCommand.ErrorExitCode, JournalCommand.ExitCodeForException(transportFailure));
        Assert.Equal(JournalCommand.ErrorExitCode, JournalCommand.ExitCodeForException(journalFailure));
    }
}
