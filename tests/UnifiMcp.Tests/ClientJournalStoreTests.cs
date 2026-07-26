using Microsoft.Data.Sqlite;
using UnifiMcp.Configuration;
using UnifiMcp.Journal;

namespace UnifiMcp.Tests;

public sealed class ClientJournalStoreTests
{
    private const string SiteId = "6cc5f1b8-cec7-4c50-9b92-805b73892756";

    [Fact]
    public void Disabled_and_not_initialized_health_do_not_create_files()
    {
        using var directory = TemporaryPrivateDirectory.Create();
        var path = Path.Combine(directory.Path, "journal.db");

        var disabled = new ClientJournalStore(Configuration(path, enabled: false));
        Assert.Equal("disabled", disabled.Inspect().State);
        Assert.False(File.Exists(path));

        var enabled = new ClientJournalStore(Configuration(path, enabled: true));
        Assert.Equal("notInitialized", enabled.Inspect().State);
        Assert.False(File.Exists(path));
    }

    [Fact]
    public async Task Explicit_initialization_creates_a_missing_private_parent()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        using var directory = TemporaryPrivateDirectory.Create();
        var parent = Path.Combine(directory.Path, "journal");
        var path = Path.Combine(parent, "client.db");
        var store = new ClientJournalStore(Configuration(path, enabled: true));

        await store.InitializeAsync(TestContext.Current.CancellationToken);

        Assert.True(Directory.Exists(parent));
        Assert.Equal(
            UnixFileMode.UserRead |
            UnixFileMode.UserWrite |
            UnixFileMode.UserExecute,
            File.GetUnixFileMode(parent));
        Assert.Equal(
            UnixFileMode.UserRead | UnixFileMode.UserWrite,
            File.GetUnixFileMode(path));
    }

    [Fact]
    public async Task Persist_creates_migrated_private_wal_journal_with_projected_columns_only()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }
        using var directory = TemporaryPrivateDirectory.Create();
        var path = Path.Combine(directory.Path, "journal.db");
        var store = new ClientJournalStore(Configuration(path, enabled: true));

        await store.PersistAsync(Collection(
            "collection-1",
            DateTimeOffset.Parse("2026-07-26T12:00:00.0000000+00:00"),
            connected: CompleteClients(Client("aa:bb:cc:dd:ee:01", "Laptop", "192.0.2.5")),
            history: CompleteHistory(Client("aa:bb:cc:dd:ee:02", "Phone", "2001:db8::2")),
            groups: CompleteGroups(Group("0123456789abcdef01234567", "Trusted", "aa:bb:cc:dd:ee:01"))),
            CancellationToken.None);

        var health = store.Inspect();
        Assert.Equal("healthy", health.State);
        Assert.Equal(1, health.SchemaVersion);
        Assert.Equal("wal", health.WalMode, ignoreCase: true);
        Assert.True(File.Exists(path));
        Assert.Equal(
            UnixFileMode.UserRead | UnixFileMode.UserWrite,
            File.GetUnixFileMode(path));

        using var connection = new SqliteConnection($"Data Source={path};Mode=ReadOnly");
        connection.Open();
        using (var autoVacuum = connection.CreateCommand())
        {
            autoVacuum.CommandText = "PRAGMA auto_vacuum;";
            Assert.Equal(2L, (long)autoVacuum.ExecuteScalar()!);
        }

        using var tables = connection.CreateCommand();
        tables.CommandText =
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;";
        var names = new List<string>();
        using (var reader = tables.ExecuteReader())
        {
            while (reader.Read())
            {
                names.Add(reader.GetString(0));
            }
        }

        Assert.Contains("client_observations", names);
        Assert.Contains("observation_field_provenance", names);
        Assert.DoesNotContain(names, name =>
            name.Contains("raw", StringComparison.OrdinalIgnoreCase) ||
            name.Contains("credential", StringComparison.OrdinalIgnoreCase) ||
            name.Contains("token", StringComparison.OrdinalIgnoreCase));

        using var columns = connection.CreateCommand();
        columns.CommandText = "SELECT sql FROM sqlite_master WHERE type='table';";
        var schema = new List<string>();
        using (var reader = columns.ExecuteReader())
        {
            while (reader.Read())
            {
                schema.Add(reader.GetString(0));
            }
        }

        var joined = string.Join("\n", schema);
        Assert.DoesNotContain("raw_response", joined, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("request_body", joined, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("api_key", joined, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Partial_source_rows_are_positive_evidence_and_not_complete_baselines()
    {
        using var directory = TemporaryPrivateDirectory.Create();
        var store = new ClientJournalStore(
            Configuration(Path.Combine(directory.Path, "journal.db"), enabled: true));
        var first = DateTimeOffset.Parse("2026-07-26T12:00:00.0000000+00:00");
        await store.PersistAsync(Collection(
            "complete-1",
            first,
            connected: CompleteClients(
                Client("aa:bb:cc:dd:ee:01", "One", null),
                Client("aa:bb:cc:dd:ee:02", "Two", null)),
            history: CompleteHistory(),
            groups: CompleteGroups()),
            CancellationToken.None);
        await store.PersistAsync(Collection(
            "partial-2",
            first.AddHours(1),
            connected: new SourceCollection<NormalizedClientObservation>(
                ClientObservationSource.OfficialConnected,
                CollectionSourceStatus.Partial,
                new[] { Client("aa:bb:cc:dd:ee:01", "One", null) },
                "controllerReadFailed",
                "safe fixed error"),
            history: CompleteHistory(),
            groups: CompleteGroups()),
            CancellationToken.None);

        var collections = store.ReadCollections(SiteId);
        Assert.Equal(2, collections.Count);
        Assert.Equal(
            "partial",
            collections.Single(value => value.CollectionId == "partial-2")
                .Sources.Single(value => value.SourceKind == "officialConnected").Status);
        Assert.Single(
            store.ReadSnapshot("partial-2", "officialConnected").Clients);
    }

    [Fact]
    public async Task History_is_chronological_normalized_and_keeps_provenance()
    {
        using var directory = TemporaryPrivateDirectory.Create();
        var store = new ClientJournalStore(
            Configuration(Path.Combine(directory.Path, "journal.db"), enabled: true));
        var first = DateTimeOffset.Parse("2026-07-26T12:00:00.0000000+00:00");
        await store.PersistAsync(Collection(
            "later",
            first.AddHours(1),
            connected: CompleteClients(Client("AA:BB:CC:DD:EE:01", "Later", "192.0.2.2")),
            history: CompleteHistory(),
            groups: CompleteGroups()),
            CancellationToken.None);
        await store.PersistAsync(Collection(
            "earlier",
            first,
            connected: CompleteClients(Client("aa:bb:cc:dd:ee:01", "Earlier", "192.0.2.1")),
            history: CompleteHistory(),
            groups: CompleteGroups()),
            CancellationToken.None);

        var rows = store.ReadClientHistory(
            "aa:bb:cc:dd:ee:01",
            SiteId,
            null,
            null);

        Assert.Equal(new[] { "earlier", "later" }, rows.Select(value => value.CollectionId));
        Assert.All(rows, row => Assert.Equal("officialConnected", row.SourceKind));
        Assert.All(rows, row => Assert.Contains(
            row.Provenance,
            value => value.FieldName == "macAddress" && value.Available));
    }

    [Fact]
    public async Task Symlink_database_path_is_rejected()
    {
        using var directory = TemporaryPrivateDirectory.Create();
        var target = Path.Combine(directory.Path, "target.db");
        File.WriteAllBytes(target, Array.Empty<byte>());
        var link = Path.Combine(directory.Path, "journal.db");
        File.CreateSymbolicLink(link, target);
        var store = new ClientJournalStore(Configuration(link, enabled: true));

        await Assert.ThrowsAsync<ConfigurationException>(
            () => store.InitializeAsync(CancellationToken.None));
    }

    [Fact]
    public async Task Corruption_requires_explicit_matching_fingerprint_recovery()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }
        using var directory = TemporaryPrivateDirectory.Create();
        var path = Path.Combine(directory.Path, "journal.db");
        File.WriteAllText(path, "not a sqlite database");
        File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        var store = new ClientJournalStore(Configuration(path, enabled: true));

        var health = store.Inspect();
        Assert.Equal("corrupt", health.State);
        Assert.NotNull(health.CorruptionFingerprint);
        await Assert.ThrowsAsync<ClientJournalRecoveryException>(
            () => store.RecoverAsync("wrong", CancellationToken.None));

        File.AppendAllText(path, "changed");
        var changedHealth = store.Inspect();
        Assert.NotEqual(
            health.CorruptionFingerprint,
            changedHealth.CorruptionFingerprint);
        await Assert.ThrowsAsync<ClientJournalRecoveryException>(
            () => store.RecoverAsync(
                health.CorruptionFingerprint!,
                TestContext.Current.CancellationToken));

        await store.RecoverAsync(
            changedHealth.CorruptionFingerprint!,
            TestContext.Current.CancellationToken);

        Assert.Equal("healthy", store.Inspect().State);
        Assert.Single(Directory.EnumerateDirectories(
            directory.Path,
            "journal.db.quarantine-*"));
    }

    [Fact]
    public async Task Failed_recovery_restores_the_corrupt_active_set()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        using var directory = TemporaryPrivateDirectory.Create();
        var path = Path.Combine(directory.Path, "journal.db");
        File.WriteAllText(path, "original corrupt bytes");
        File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        var configuration = Configuration(path, enabled: true);
        var store = new ClientJournalStore(
            configuration,
            _ => throw new InvalidOperationException("Injected recovery initialization failure."));
        var health = store.Inspect();

        var exception = await Assert.ThrowsAsync<ClientJournalRecoveryException>(
            () => store.RecoverAsync(
                health.CorruptionFingerprint!,
                TestContext.Current.CancellationToken));

        Assert.Contains("restored", exception.Message, StringComparison.Ordinal);
        Assert.Equal("original corrupt bytes", File.ReadAllText(path));
        Assert.Equal("corrupt", new ClientJournalStore(configuration).Inspect().State);
        Assert.Empty(Directory.EnumerateDirectories(
            directory.Path,
            "journal.db.quarantine-*"));
    }

    [Theory]
    [InlineData(0, "migrationRequired")]
    [InlineData(2, "newerSchemaNotSupported")]
    public async Task Read_only_health_reports_schema_state_without_migrating(
        int userVersion,
        string expectedState)
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        using var directory = TemporaryPrivateDirectory.Create();
        var path = Path.Combine(directory.Path, "journal.db");
        using (var connection = new SqliteConnection($"Data Source={path}"))
        {
            connection.Open();
            using var command = connection.CreateCommand();
            command.CommandText = $"PRAGMA user_version={userVersion};";
            command.ExecuteNonQuery();
        }

        File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        var store = new ClientJournalStore(Configuration(path, enabled: true));
        var before = new FileInfo(path).LastWriteTimeUtc;

        Assert.Equal(expectedState, store.Inspect().State);
        Assert.Equal(before, new FileInfo(path).LastWriteTimeUtc);
        if (userVersion > 1)
        {
            await Assert.ThrowsAsync<ClientJournalMigrationException>(
                () => store.InitializeAsync(TestContext.Current.CancellationToken));
            using var connection = new SqliteConnection($"Data Source={path};Mode=ReadOnly");
            connection.Open();
            using var command = connection.CreateCommand();
            command.CommandText = "PRAGMA user_version;";
            Assert.Equal(2L, Convert.ToInt64(command.ExecuteScalar()));
        }
    }

    [Fact]
    public async Task Health_reports_unsafe_permissions_without_repairing_them()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        using var directory = TemporaryPrivateDirectory.Create();
        var path = Path.Combine(directory.Path, "journal.db");
        var store = new ClientJournalStore(Configuration(path, enabled: true));
        await store.InitializeAsync(TestContext.Current.CancellationToken);
        File.SetUnixFileMode(
            path,
            UnixFileMode.UserRead |
            UnixFileMode.UserWrite |
            UnixFileMode.GroupRead);

        var health = store.Inspect();

        Assert.Equal("unsafePath", health.State);
        Assert.True((File.GetUnixFileMode(path) & UnixFileMode.GroupRead) != 0);
        Assert.Throws<ClientJournalUnavailableException>(
            () => store.ReadCollections(SiteId));
    }

    [Fact]
    public async Task Migration_failure_rolls_back_and_a_later_initialization_can_retry()
    {
        using var directory = TemporaryPrivateDirectory.Create();
        var path = Path.Combine(directory.Path, "journal.db");
        var configuration = Configuration(path, enabled: true);
        var failing = new ClientJournalStore(
            configuration,
            version => throw new InvalidOperationException(
                $"Injected migration {version} failure."));

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => failing.InitializeAsync(TestContext.Current.CancellationToken));

        var afterFailure = new ClientJournalStore(configuration).Inspect();
        Assert.Equal("migrationRequired", afterFailure.State);
        var retry = new ClientJournalStore(configuration);
        await retry.InitializeAsync(TestContext.Current.CancellationToken);
        Assert.Equal("healthy", retry.Inspect().State);
    }

    [Fact]
    public async Task Migration_checksum_mismatch_fails_closed()
    {
        using var directory = TemporaryPrivateDirectory.Create();
        var path = Path.Combine(directory.Path, "journal.db");
        var configuration = Configuration(path, enabled: true);
        var store = new ClientJournalStore(configuration);
        await store.InitializeAsync(TestContext.Current.CancellationToken);
        SqliteConnection.ClearAllPools();
        using (var connection = new SqliteConnection($"Data Source={path}"))
        {
            connection.Open();
            using var command = connection.CreateCommand();
            command.CommandText =
                "UPDATE schema_migrations SET checksum='tampered' WHERE version=1;";
            command.ExecuteNonQuery();
        }
        SetPrivateActiveFiles(path);

        Assert.Equal("corrupt", store.Inspect().State);
        await Assert.ThrowsAsync<ClientJournalMigrationException>(
            () => store.InitializeAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task Missing_incremental_auto_vacuum_fails_closed()
    {
        using var directory = TemporaryPrivateDirectory.Create();
        var path = Path.Combine(directory.Path, "journal.db");
        var configuration = Configuration(path, enabled: true);
        var store = new ClientJournalStore(configuration);
        await store.InitializeAsync(TestContext.Current.CancellationToken);
        SqliteConnection.ClearAllPools();
        using (var connection = new SqliteConnection($"Data Source={path}"))
        {
            connection.Open();
            using var command = connection.CreateCommand();
            command.CommandText =
                "PRAGMA journal_mode=DELETE; PRAGMA auto_vacuum=NONE; VACUUM;";
            command.ExecuteNonQuery();
        }
        SetPrivateActiveFiles(path);

        var health = store.Inspect();

        Assert.Equal("corrupt", health.State);
        Assert.Contains(
            "incremental auto-vacuum",
            health.Reason,
            StringComparison.OrdinalIgnoreCase);
        await Assert.ThrowsAsync<ClientJournalMigrationException>(
            () => store.InitializeAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task Retention_deletes_whole_old_collections()
    {
        using var directory = TemporaryPrivateDirectory.Create();
        var path = Path.Combine(directory.Path, "journal.db");
        var configuration = Configuration(path, enabled: true) with
        {
            ClientJournalRetentionDays = 1
        };
        var store = new ClientJournalStore(configuration);
        var recent = DateTimeOffset.Parse("2026-07-26T12:00:00.0000000+00:00");
        await store.PersistAsync(Collection(
            "old",
            recent.AddDays(-2),
            CompleteClients(Client("aa:bb:cc:dd:ee:01", "Old", null)),
            CompleteHistory(),
            CompleteGroups()),
            TestContext.Current.CancellationToken);
        await store.PersistAsync(Collection(
            "recent",
            recent,
            CompleteClients(Client("aa:bb:cc:dd:ee:02", "Recent", null)),
            CompleteHistory(),
            CompleteGroups()),
            TestContext.Current.CancellationToken);

        var collections = store.ReadCollections(SiteId);
        Assert.Single(collections);
        Assert.Equal("recent", collections[0].CollectionId);
        Assert.Empty(store.ReadSnapshot("old", "officialConnected").Clients);
    }

    [Fact]
    public async Task Competing_local_writes_are_serialized_and_atomic()
    {
        using var directory = TemporaryPrivateDirectory.Create();
        var store = new ClientJournalStore(
            Configuration(Path.Combine(directory.Path, "journal.db"), enabled: true));
        var observedAt = DateTimeOffset.Parse("2026-07-26T12:00:00.0000000+00:00");
        var tasks = Enumerable.Range(0, 8)
            .Select(index => store.PersistAsync(Collection(
                $"collection-{index:D2}",
                observedAt.AddMinutes(index),
                CompleteClients(Client(Mac(index), $"Client {index}", null)),
                CompleteHistory(),
                CompleteGroups()),
                TestContext.Current.CancellationToken))
            .ToArray();

        await Task.WhenAll(tasks);

        Assert.Equal(8, store.ReadCollections(SiteId).Count);
        Assert.All(
            store.ReadCollections(SiteId),
            collection => Assert.Equal(3, collection.Sources.Count));
    }

    [Fact]
    public async Task Wal_reader_keeps_a_stable_snapshot_during_a_collection()
    {
        using var directory = TemporaryPrivateDirectory.Create();
        var path = Path.Combine(directory.Path, "journal.db");
        var configuration = Configuration(path, enabled: true);
        var store = new ClientJournalStore(configuration);
        var observedAt = DateTimeOffset.Parse("2026-07-26T12:00:00.0000000+00:00");
        await store.PersistAsync(Collection(
            "first",
            observedAt,
            CompleteClients(Client("aa:bb:cc:dd:ee:01", "One", null)),
            CompleteHistory(),
            CompleteGroups()),
            TestContext.Current.CancellationToken);

        using var readerConnection = new SqliteConnection(
            $"Data Source={path};Mode=ReadOnly");
        readerConnection.Open();
        using var readerTransaction = readerConnection.BeginTransaction();
        Assert.Equal(1L, CountCollections(readerConnection, readerTransaction));

        await store.PersistAsync(Collection(
            "second",
            observedAt.AddMinutes(1),
            CompleteClients(Client("aa:bb:cc:dd:ee:02", "Two", null)),
            CompleteHistory(),
            CompleteGroups()),
            TestContext.Current.CancellationToken);

        Assert.Equal(1L, CountCollections(readerConnection, readerTransaction));
        readerTransaction.Commit();
        Assert.Equal(2L, CountCollections(readerConnection, transaction: null));

        var restartedStore = new ClientJournalStore(configuration);
        Assert.Equal(2, restartedStore.ReadCollections(SiteId).Count);
    }

    [Fact]
    public async Task Oversized_store_rejects_and_rolls_back_a_collection()
    {
        using var directory = TemporaryPrivateDirectory.Create();
        var path = Path.Combine(directory.Path, "journal.db");
        var configuration = Configuration(path, enabled: true);
        var store = new ClientJournalStore(configuration);
        await store.InitializeAsync(TestContext.Current.CancellationToken);
        SqliteConnection.ClearAllPools();
        using (var connection = new SqliteConnection($"Data Source={path}"))
        {
            connection.Open();
            using var command = connection.CreateCommand();
            command.CommandText =
                "PRAGMA max_page_count=10000;" +
                "CREATE TABLE size_test(payload BLOB);" +
                "INSERT INTO size_test(payload) VALUES(zeroblob(17825792));" +
                "PRAGMA wal_checkpoint(TRUNCATE);";
            command.ExecuteNonQuery();
        }
        SetPrivateActiveFiles(path);

        var health = store.Inspect();
        Assert.True(health.Oversized);
        await Assert.ThrowsAsync<ClientJournalSizeException>(
            () => store.PersistAsync(Collection(
                "must-not-commit",
                DateTimeOffset.Parse("2026-07-26T12:00:00.0000000+00:00"),
                CompleteClients(Client("aa:bb:cc:dd:ee:01", "One", null)),
                CompleteHistory(),
                CompleteGroups()),
                TestContext.Current.CancellationToken));
        Assert.Empty(store.ReadCollections(SiteId));
    }

    private static UnifiConfiguration Configuration(string path, bool enabled) =>
        new(
            new Uri("https://example.test/proxy/network/integration/"),
            "test-key",
            SiteId,
            TimeSpan.FromSeconds(30),
            EnableLegacyReadEnrichment: true,
            EnableClientJournal: enabled,
            ClientJournalDatabasePath: path,
            ClientJournalRetentionDays: 90,
            ClientJournalMaximumMib: 16);

    private static ClientObservationCollection Collection(
        string id,
        DateTimeOffset timestamp,
        SourceCollection<NormalizedClientObservation> connected,
        SourceCollection<NormalizedClientObservation> history,
        SourceCollection<NormalizedClientGroup> groups) =>
        new(
            id,
            SiteId,
            24,
            timestamp.AddSeconds(-1),
            timestamp,
            connected,
            history,
            groups);

    private static SourceCollection<NormalizedClientObservation> CompleteClients(
        params NormalizedClientObservation[] records) =>
        new(
            ClientObservationSource.OfficialConnected,
            CollectionSourceStatus.Complete,
            records,
            null,
            null);

    private static SourceCollection<NormalizedClientObservation> CompleteHistory(
        params NormalizedClientObservation[] records) =>
        new(
            ClientObservationSource.UiHistory,
            CollectionSourceStatus.Complete,
            records,
            null,
            null);

    private static SourceCollection<NormalizedClientGroup> CompleteGroups(
        params NormalizedClientGroup[] records) =>
        new(
            ClientObservationSource.ConfiguredGroups,
            CollectionSourceStatus.Complete,
            records,
            null,
            null);

    private static NormalizedClientObservation Client(
        string mac,
        string? name,
        string? ip) =>
        new(
            mac.ToLowerInvariant(),
            name,
            ip,
            "online",
            null,
            null,
            new[]
            {
                new FieldEvidence("macAddress", "macAddress", "authoritative-current", true),
                new FieldEvidence("name", "name", "authoritative-current", name is not null),
                new FieldEvidence("ipAddress", "ipAddress", "authoritative-current", ip is not null)
            });

    private static NormalizedClientGroup Group(
        string id,
        string name,
        params string[] members) =>
        new(id, name, members.Select(value => value.ToLowerInvariant()).ToArray());

    private static string Mac(int index) =>
        $"02:00:00:00:{(index >> 8) & 0xff:x2}:{index & 0xff:x2}";

    private static long CountCollections(
        SqliteConnection connection,
        SqliteTransaction? transaction)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "SELECT count(*) FROM collections;";
        return Convert.ToInt64(command.ExecuteScalar());
    }

    private static void SetPrivateActiveFiles(string databasePath)
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        foreach (var path in new[]
                 {
                     databasePath,
                     databasePath + "-wal",
                     databasePath + "-shm"
                 }.Where(File.Exists))
        {
            File.SetUnixFileMode(
                path,
                UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
    }
}

internal sealed class TemporaryPrivateDirectory : IDisposable
{
    private TemporaryPrivateDirectory(string path)
    {
        Path = path;
    }

    public string Path { get; }

    public static TemporaryPrivateDirectory Create()
    {
        if (OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException(
                "Journal permission tests require Unix filesystem modes.");
        }

        var path = System.IO.Path.Combine(
            System.IO.Path.GetTempPath(),
            "unifi-mcp-journal-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(path);
        File.SetUnixFileMode(
            path,
            UnixFileMode.UserRead |
            UnixFileMode.UserWrite |
            UnixFileMode.UserExecute);
        return new TemporaryPrivateDirectory(path);
    }

    public void Dispose()
    {
        if (Directory.Exists(Path))
        {
            Directory.Delete(Path, recursive: true);
        }
    }
}
