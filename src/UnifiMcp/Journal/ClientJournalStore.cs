using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.Sqlite;
using UnifiMcp.Configuration;

namespace UnifiMcp.Journal;

public sealed class ClientJournalStore
{
    private const int CurrentSchemaVersion = 1;
    private const int BusyTimeoutMilliseconds = 5000;
    private static readonly SemaphoreSlim WriteSemaphore = new(1, 1);

    private static readonly ClientJournalMigration[] Migrations =
    {
        new(
            1,
            @"
            CREATE TABLE schema_migrations (
                version INTEGER NOT NULL PRIMARY KEY,
                checksum TEXT NOT NULL,
                applied_at_ms INTEGER NOT NULL
            ) STRICT;
            CREATE TABLE collections (
                collection_id TEXT NOT NULL PRIMARY KEY,
                site_id TEXT NOT NULL,
                started_at_ms INTEGER NOT NULL,
                completed_at_ms INTEGER NOT NULL,
                history_hours INTEGER NOT NULL CHECK (history_hours IN (24,72,168,336,720,4320)),
                overall_status TEXT NOT NULL CHECK (overall_status IN ('complete','partial','failed'))
            ) STRICT;
            CREATE INDEX collections_site_time
                ON collections(site_id, completed_at_ms DESC, collection_id DESC);
            CREATE TABLE collection_sources (
                collection_id TEXT NOT NULL REFERENCES collections(collection_id) ON DELETE CASCADE,
                source_kind TEXT NOT NULL CHECK (source_kind IN ('officialConnected','uiHistory','configuredGroups')),
                status TEXT NOT NULL CHECK (status IN ('complete','partial','failed')),
                record_count INTEGER NOT NULL CHECK (record_count >= 0),
                error_code TEXT,
                error_message TEXT,
                PRIMARY KEY (collection_id, source_kind)
            ) STRICT;
            CREATE INDEX collection_sources_status
                ON collection_sources(source_kind, status, collection_id);
            CREATE TABLE client_observations (
                observation_id INTEGER NOT NULL PRIMARY KEY,
                collection_id TEXT NOT NULL REFERENCES collections(collection_id) ON DELETE CASCADE,
                source_kind TEXT NOT NULL CHECK (source_kind IN ('officialConnected','uiHistory')),
                mac_address TEXT NOT NULL COLLATE NOCASE,
                client_name TEXT,
                ip_address TEXT,
                observed_state TEXT CHECK (observed_state IN ('online','historyEvidence','offline')),
                connected_at_ms INTEGER,
                last_seen_at_ms INTEGER,
                UNIQUE (collection_id, source_kind, mac_address)
            ) STRICT;
            CREATE INDEX client_observations_mac_time
                ON client_observations(mac_address, collection_id, source_kind);
            CREATE TABLE observation_field_provenance (
                observation_id INTEGER NOT NULL REFERENCES client_observations(observation_id) ON DELETE CASCADE,
                field_name TEXT NOT NULL,
                source_field TEXT NOT NULL,
                authority TEXT NOT NULL,
                available INTEGER NOT NULL CHECK (available IN (0,1)),
                PRIMARY KEY (observation_id, field_name)
            ) STRICT;
            CREATE TABLE group_observations (
                collection_id TEXT NOT NULL REFERENCES collections(collection_id) ON DELETE CASCADE,
                group_id TEXT NOT NULL,
                group_name TEXT NOT NULL,
                PRIMARY KEY (collection_id, group_id)
            ) STRICT;
            CREATE TABLE group_memberships (
                collection_id TEXT NOT NULL REFERENCES collections(collection_id) ON DELETE CASCADE,
                group_id TEXT NOT NULL,
                mac_address TEXT NOT NULL COLLATE NOCASE,
                PRIMARY KEY (collection_id, group_id, mac_address),
                FOREIGN KEY (collection_id, group_id)
                    REFERENCES group_observations(collection_id, group_id) ON DELETE CASCADE
            ) STRICT;
            CREATE INDEX group_memberships_mac
                ON group_memberships(mac_address, collection_id);
            PRAGMA user_version=1;
            ")
    };

    private readonly UnifiConfiguration _configuration;
    private readonly Action<int>? _beforeMigrationCommit;

    public ClientJournalStore(UnifiConfiguration configuration)
        : this(configuration, beforeMigrationCommit: null)
    {
    }

    internal ClientJournalStore(
        UnifiConfiguration configuration,
        Action<int>? beforeMigrationCommit)
    {
        _configuration = configuration;
        _beforeMigrationCommit = beforeMigrationCommit;
    }

    public bool Enabled => _configuration.EnableClientJournal;

    public string DatabasePath =>
        _configuration.ClientJournalDatabasePath ??
        throw new ConfigurationException("The client journal database path is not configured.");

    public async Task InitializeAsync(CancellationToken cancellationToken)
    {
        RequireEnabled();
        await WriteSemaphore.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            EnsureWritablePath();
            using var connection = OpenWritableConnection();
            RejectNewerSchema(connection);
            ConfigureIncrementalAutoVacuum(connection);
            ConfigureWritableConnection(connection);
            ApplyPrivateFileModes();
            ApplyMigrations(connection);
            RequireIncrementalAutoVacuum(connection);
            ApplyPrivateFileModes();
        }
        finally
        {
            WriteSemaphore.Release();
        }
    }

    public async Task PersistAsync(
        ClientObservationCollection collection,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(collection);
        RequireEnabled();

        await WriteSemaphore.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            EnsureWritablePath();
            using var connection = OpenWritableConnection();
            RejectNewerSchema(connection);
            ConfigureIncrementalAutoVacuum(connection);
            ConfigureWritableConnection(connection);
            ApplyPrivateFileModes();
            ApplyMigrations(connection);
            RequireIncrementalAutoVacuum(connection);
            PruneExpiredCollections(connection, collection.CompletedAt);
            PruneForSize(connection);

            using var transaction = connection.BeginTransaction();
            InsertCollection(connection, transaction, collection);
            if (GetActiveBytes() > MaximumBytes)
            {
                transaction.Rollback();
                Checkpoint(connection, truncate: true);
                throw new ClientJournalSizeException(
                    "The projected collection could not fit within UNIFI_CLIENT_JOURNAL_MAX_MIB; it was rolled back.");
            }

            transaction.Commit();
            Checkpoint(connection, truncate: false);
            ApplyPrivateFileModes();
            PruneForSize(connection);
            if (GetActiveBytes() > MaximumBytes)
            {
                throw new ClientJournalSizeException(
                    "The active journal remains over its configured size cap after whole-collection pruning.");
            }
        }
        finally
        {
            WriteSemaphore.Release();
        }
    }

    public JournalInspection Inspect()
    {
        if (!Enabled)
        {
            return JournalInspection.Disabled(
                _configuration.ClientJournalRetentionDays,
                _configuration.ClientJournalMaximumMib);
        }

        var path = DatabasePath;
        if (!File.Exists(path))
        {
            return JournalInspection.NotInitialized(
                _configuration.ClientJournalRetentionDays,
                _configuration.ClientJournalMaximumMib,
                GetQuarantineInventory());
        }

        try
        {
            ValidateExistingPathForRead();
            using var connection = OpenReadOnlyConnection();
            var schema = ReadSchemaStatus(connection);
            if (schema.State != "healthy")
            {
                return schema with
                {
                    ActiveBytes = GetActiveBytes(),
                    Oversized = GetActiveBytes() > MaximumBytes,
                    Quarantine = GetQuarantineInventory()
                };
            }

            using var check = connection.CreateCommand();
            check.CommandText = "PRAGMA quick_check(1);";
            var checkResult = Convert.ToString(check.ExecuteScalar(), CultureInfo.InvariantCulture);
            if (!string.Equals(checkResult, "ok", StringComparison.Ordinal))
            {
                return JournalInspection.Corrupt(
                    CreateCorruptionFingerprint(),
                    "SQLite quick_check did not return ok.",
                    _configuration.ClientJournalRetentionDays,
                    _configuration.ClientJournalMaximumMib,
                    GetActiveBytes(),
                    GetQuarantineInventory());
            }

            var details = ReadHealthDetails(connection);
            return schema with
            {
                ActiveBytes = GetActiveBytes(),
                Oversized = GetActiveBytes() > MaximumBytes,
                LastCollections = details.LastCollections,
                SourceSuccessRates = details.SourceSuccessRates,
                Quarantine = GetQuarantineInventory()
            };
        }
        catch (Exception exception) when (IsDatabaseFailure(exception))
        {
            return JournalInspection.Corrupt(
                CreateCorruptionFingerprint(),
                "The active SQLite journal could not be validated.",
                _configuration.ClientJournalRetentionDays,
                _configuration.ClientJournalMaximumMib,
                GetActiveBytes(),
                GetQuarantineInventory());
        }
        catch (ConfigurationException)
        {
            return JournalInspection.UnsafePath(
                "The configured journal path is symlinked or its active permissions are not private.",
                _configuration.ClientJournalRetentionDays,
                _configuration.ClientJournalMaximumMib,
                GetActiveBytes(),
                GetQuarantineInventory());
        }
    }

    public IReadOnlyList<StoredCollection> ReadCollections(string? siteId = null)
    {
        using var connection = OpenValidatedReadOnlyConnection();
        using var command = connection.CreateCommand();
        command.CommandText =
            @"
            SELECT c.collection_id, c.site_id, c.started_at_ms, c.completed_at_ms,
                   c.history_hours, c.overall_status,
                   s.source_kind, s.status, s.record_count, s.error_code, s.error_message
            FROM collections c
            JOIN collection_sources s ON s.collection_id = c.collection_id
            WHERE ($site_id IS NULL OR c.site_id = $site_id)
            ORDER BY c.completed_at_ms, c.collection_id, s.source_kind;
            ";
        command.Parameters.AddWithValue("$site_id", (object?)siteId ?? DBNull.Value);

        var builders = new Dictionary<string, StoredCollectionBuilder>(StringComparer.Ordinal);
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            var id = reader.GetString(0);
            if (!builders.TryGetValue(id, out var builder))
            {
                builder = new StoredCollectionBuilder(
                    id,
                    reader.GetString(1),
                    reader.GetInt64(2),
                    reader.GetInt64(3),
                    reader.GetInt32(4),
                    reader.GetString(5));
                builders.Add(id, builder);
            }

            builder.Sources.Add(new StoredSource(
                reader.GetString(6),
                reader.GetString(7),
                reader.GetInt32(8),
                reader.IsDBNull(9) ? null : reader.GetString(9),
                reader.IsDBNull(10) ? null : reader.GetString(10)));
        }

        return builders.Values
            .Select(value => value.Build())
            .OrderBy(value => value.CompletedAtMilliseconds)
            .ThenBy(value => value.CollectionId, StringComparer.Ordinal)
            .ToArray();
    }

    public StoredSnapshot ReadSnapshot(string collectionId, string sourceKind)
    {
        using var connection = OpenValidatedReadOnlyConnection();
        var clients = ReadClientSnapshot(connection, collectionId, sourceKind);
        var groups = string.Equals(
                sourceKind,
                ClientJournalValues.Source(ClientObservationSource.ConfiguredGroups),
                StringComparison.Ordinal)
            ? ReadGroupSnapshot(connection, collectionId)
            : Array.Empty<StoredGroup>();
        return new StoredSnapshot(clients, groups);
    }

    public IReadOnlyList<StoredClientHistoryRow> ReadClientHistory(
        string macAddress,
        string? siteId,
        long? fromMilliseconds,
        long? toMilliseconds)
    {
        using var connection = OpenValidatedReadOnlyConnection();
        using var command = connection.CreateCommand();
        command.CommandText =
            @"
            SELECT c.collection_id, c.site_id, c.completed_at_ms, c.history_hours,
                   s.source_kind, s.status,
                   o.client_name, o.ip_address, o.observed_state,
                   o.connected_at_ms, o.last_seen_at_ms, o.observation_id
            FROM client_observations o
            JOIN collections c ON c.collection_id = o.collection_id
            JOIN collection_sources s
              ON s.collection_id = o.collection_id AND s.source_kind = o.source_kind
            WHERE o.mac_address = $mac
              AND ($site_id IS NULL OR c.site_id = $site_id)
              AND ($from_ms IS NULL OR c.completed_at_ms >= $from_ms)
              AND ($to_ms IS NULL OR c.completed_at_ms <= $to_ms)
            ORDER BY c.completed_at_ms, c.collection_id, s.source_kind;
            ";
        command.Parameters.AddWithValue("$mac", macAddress);
        command.Parameters.AddWithValue("$site_id", (object?)siteId ?? DBNull.Value);
        command.Parameters.AddWithValue("$from_ms", (object?)fromMilliseconds ?? DBNull.Value);
        command.Parameters.AddWithValue("$to_ms", (object?)toMilliseconds ?? DBNull.Value);

        var pending = new List<(StoredClientHistoryRow Row, long ObservationId)>();
        using (var reader = command.ExecuteReader())
        {
            while (reader.Read())
            {
                pending.Add((
                    new StoredClientHistoryRow(
                        reader.GetString(0),
                        reader.GetString(1),
                        reader.GetInt64(2),
                        reader.GetInt32(3),
                        reader.GetString(4),
                        reader.GetString(5),
                        reader.IsDBNull(6) ? null : reader.GetString(6),
                        reader.IsDBNull(7) ? null : reader.GetString(7),
                        reader.IsDBNull(8) ? null : reader.GetString(8),
                        reader.IsDBNull(9) ? null : reader.GetInt64(9),
                        reader.IsDBNull(10) ? null : reader.GetInt64(10),
                        Array.Empty<FieldEvidence>()),
                    reader.GetInt64(11)));
            }
        }

        return pending
            .Select(value => value.Row with
            {
                Provenance = ReadProvenance(connection, value.ObservationId)
            })
            .ToArray();
    }

    public async Task RecoverAsync(
        string expectedFingerprint,
        CancellationToken cancellationToken)
    {
        RequireEnabled();
        if (string.IsNullOrWhiteSpace(expectedFingerprint))
        {
            throw new ClientJournalRecoveryException(
                "corruptionFingerprint is required.");
        }

        await WriteSemaphore.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var inspection = Inspect();
            if (!string.Equals(inspection.State, "corrupt", StringComparison.Ordinal) ||
                !string.Equals(
                    inspection.CorruptionFingerprint,
                    expectedFingerprint,
                    StringComparison.Ordinal))
            {
                throw new ClientJournalRecoveryException(
                    "The active journal is not corrupt or its corruption fingerprint changed. Run health again.");
            }

            var quarantineDirectory = GetNewQuarantineDirectory(expectedFingerprint);
            Directory.CreateDirectory(quarantineDirectory);
            SetDirectoryPrivate(quarantineDirectory);
            var moved = new List<(string Original, string Quarantined)>();
            try
            {
                SqliteConnection.ClearAllPools();
                foreach (var activePath in ActivePaths().Where(File.Exists))
                {
                    var quarantined = Path.Combine(
                        quarantineDirectory,
                        Path.GetFileName(activePath));
                    File.Move(activePath, quarantined);
                    moved.Add((activePath, quarantined));
                }

                EnsureWritablePath();
                using var connection = OpenWritableConnection();
                RejectNewerSchema(connection);
                ConfigureIncrementalAutoVacuum(connection);
                ConfigureWritableConnection(connection);
                ApplyPrivateFileModes();
                ApplyMigrations(connection);
                RequireIncrementalAutoVacuum(connection);
                ApplyPrivateFileModes();
            }
            catch
            {
                SqliteConnection.ClearAllPools();
                foreach (var activePath in ActivePaths().Where(File.Exists))
                {
                    File.Delete(activePath);
                }

                foreach (var item in moved)
                {
                    File.Move(item.Quarantined, item.Original);
                }

                if (!Directory.EnumerateFileSystemEntries(quarantineDirectory).Any())
                {
                    Directory.Delete(quarantineDirectory);
                }

                throw new ClientJournalRecoveryException(
                    "Fresh journal initialization failed; the quarantined active database set was restored.");
            }
        }
        finally
        {
            WriteSemaphore.Release();
        }
    }

    private long MaximumBytes =>
        checked((long)_configuration.ClientJournalMaximumMib * 1024L * 1024L);

    private void RequireEnabled()
    {
        if (!Enabled)
        {
            throw new ConfigurationException(
                "The client observation journal is disabled. Set UNIFI_ENABLE_CLIENT_JOURNAL=true and configure an absolute UNIFI_CLIENT_JOURNAL_DB_PATH.");
        }
    }

    private SqliteConnection OpenWritableConnection()
    {
        var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = DatabasePath,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Pooling = true,
            DefaultTimeout = BusyTimeoutMilliseconds / 1000
        }.ToString());
        connection.Open();
        return connection;
    }

    private SqliteConnection OpenReadOnlyConnection()
    {
        var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = DatabasePath,
            Mode = SqliteOpenMode.ReadOnly,
            Pooling = true,
            DefaultTimeout = BusyTimeoutMilliseconds / 1000
        }.ToString());
        connection.Open();
        using var timeout = connection.CreateCommand();
        timeout.CommandText = $"PRAGMA busy_timeout={BusyTimeoutMilliseconds};";
        timeout.ExecuteNonQuery();
        return connection;
    }

    private SqliteConnection OpenValidatedReadOnlyConnection()
    {
        RequireEnabled();
        var inspection = Inspect();
        if (!string.Equals(inspection.State, "healthy", StringComparison.Ordinal) &&
            !string.Equals(inspection.State, "oversized", StringComparison.Ordinal))
        {
            throw new ClientJournalUnavailableException(
                $"The client journal is not queryable because health state is {inspection.State}.");
        }

        return OpenReadOnlyConnection();
    }

    private void ConfigureWritableConnection(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText =
            $@"
            PRAGMA busy_timeout={BusyTimeoutMilliseconds};
            PRAGMA journal_mode=WAL;
            PRAGMA foreign_keys=ON;
            PRAGMA synchronous=FULL;
            PRAGMA wal_autocheckpoint=256;
            PRAGMA journal_size_limit={Math.Max(1L * 1024 * 1024, MaximumBytes / 4)};
            ";
        command.ExecuteNonQuery();

        using var pageSize = connection.CreateCommand();
        pageSize.CommandText = "PRAGMA page_size;";
        var bytesPerPage = Convert.ToInt64(pageSize.ExecuteScalar(), CultureInfo.InvariantCulture);
        using var maximumPages = connection.CreateCommand();
        maximumPages.CommandText = $"PRAGMA max_page_count={Math.Max(1, MaximumBytes / bytesPerPage)};";
        maximumPages.ExecuteNonQuery();
    }

    private static void ConfigureIncrementalAutoVacuum(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText = "PRAGMA auto_vacuum=INCREMENTAL;";
        command.ExecuteNonQuery();
    }

    private static void RequireIncrementalAutoVacuum(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText = "PRAGMA auto_vacuum;";
        var mode = Convert.ToInt32(command.ExecuteScalar(), CultureInfo.InvariantCulture);
        if (mode != 2)
        {
            throw new ClientJournalMigrationException(
                "The client journal is not configured for incremental auto-vacuum.");
        }
    }

    private static void Checkpoint(SqliteConnection connection, bool truncate)
    {
        using var command = connection.CreateCommand();
        command.CommandText = truncate
            ? "PRAGMA wal_checkpoint(TRUNCATE);"
            : "PRAGMA wal_checkpoint(PASSIVE);";
        command.ExecuteNonQuery();
    }

    private void ApplyMigrations(SqliteConnection connection)
    {
        using var detect = connection.CreateCommand();
        detect.CommandText =
            "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='schema_migrations';";
        var hasMigrations = Convert.ToInt32(detect.ExecuteScalar(), CultureInfo.InvariantCulture) == 1;

        var applied = new Dictionary<int, string>();
        if (hasMigrations)
        {
            using var read = connection.CreateCommand();
            read.CommandText = "SELECT version, checksum FROM schema_migrations ORDER BY version;";
            using var reader = read.ExecuteReader();
            while (reader.Read())
            {
                applied.Add(reader.GetInt32(0), reader.GetString(1));
            }
        }

        foreach (var migration in Migrations)
        {
            if (applied.TryGetValue(migration.Version, out var checksum))
            {
                if (!string.Equals(checksum, migration.Checksum, StringComparison.Ordinal))
                {
                    throw new ClientJournalMigrationException(
                        $"Client journal migration {migration.Version} checksum does not match the application.");
                }

                continue;
            }

            using var transaction = connection.BeginTransaction();
            using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = migration.Sql;
            command.ExecuteNonQuery();
            using var record = connection.CreateCommand();
            record.Transaction = transaction;
            record.CommandText =
                "INSERT INTO schema_migrations(version, checksum, applied_at_ms) VALUES($version, $checksum, $applied);";
            record.Parameters.AddWithValue("$version", migration.Version);
            record.Parameters.AddWithValue("$checksum", migration.Checksum);
            record.Parameters.AddWithValue("$applied", DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
            record.ExecuteNonQuery();
            _beforeMigrationCommit?.Invoke(migration.Version);
            transaction.Commit();
        }
    }

    private static void RejectNewerSchema(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText = "PRAGMA user_version;";
        var version = Convert.ToInt32(command.ExecuteScalar(), CultureInfo.InvariantCulture);
        if (version > CurrentSchemaVersion)
        {
            throw new ClientJournalMigrationException(
                $"Client journal schema {version} is newer than supported schema {CurrentSchemaVersion}.");
        }
    }

    private JournalInspection ReadSchemaStatus(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText = "PRAGMA user_version;";
        var version = Convert.ToInt32(command.ExecuteScalar(), CultureInfo.InvariantCulture);
        if (version > CurrentSchemaVersion)
        {
            return JournalInspection.NewerSchema(
                version,
                CurrentSchemaVersion,
                _configuration.ClientJournalRetentionDays,
                _configuration.ClientJournalMaximumMib);
        }

        if (version < CurrentSchemaVersion)
        {
            return JournalInspection.MigrationRequired(
                version,
                CurrentSchemaVersion,
                _configuration.ClientJournalRetentionDays,
                _configuration.ClientJournalMaximumMib);
        }

        using var migrations = connection.CreateCommand();
        migrations.CommandText =
            "SELECT version, checksum FROM schema_migrations ORDER BY version;";
        using var reader = migrations.ExecuteReader();
        var found = new Dictionary<int, string>();
        while (reader.Read())
        {
            found.Add(reader.GetInt32(0), reader.GetString(1));
        }

        if (Migrations.Any(migration =>
                !found.TryGetValue(migration.Version, out var checksum) ||
                !string.Equals(checksum, migration.Checksum, StringComparison.Ordinal)))
        {
            return JournalInspection.Corrupt(
                CreateCorruptionFingerprint(),
                "Migration checksums do not match the application.",
                _configuration.ClientJournalRetentionDays,
                _configuration.ClientJournalMaximumMib,
                GetActiveBytes(),
                GetQuarantineInventory());
        }

        using (var autoVacuum = connection.CreateCommand())
        {
            autoVacuum.CommandText = "PRAGMA auto_vacuum;";
            var mode = Convert.ToInt32(
                autoVacuum.ExecuteScalar(),
                CultureInfo.InvariantCulture);
            if (mode != 2)
            {
                return JournalInspection.Corrupt(
                    CreateCorruptionFingerprint(),
                    "The active SQLite journal is not configured for incremental auto-vacuum.",
                    _configuration.ClientJournalRetentionDays,
                    _configuration.ClientJournalMaximumMib,
                    GetActiveBytes(),
                    GetQuarantineInventory());
            }
        }

        using var wal = connection.CreateCommand();
        wal.CommandText = "PRAGMA journal_mode;";
        var journalMode = Convert.ToString(wal.ExecuteScalar(), CultureInfo.InvariantCulture);
        return JournalInspection.Healthy(
            version,
            journalMode ?? "unknown",
            _configuration.ClientJournalRetentionDays,
            _configuration.ClientJournalMaximumMib);
    }

    private static HealthDetails ReadHealthDetails(SqliteConnection connection)
    {
        var last = new List<HealthCollection>();
        using (var command = connection.CreateCommand())
        {
            command.CommandText =
                @"
                SELECT collection_id, site_id, completed_at_ms, overall_status
                FROM collections
                ORDER BY completed_at_ms DESC, collection_id DESC
                LIMIT 10;
                ";
            using var reader = command.ExecuteReader();
            while (reader.Read())
            {
                last.Add(new HealthCollection(
                    reader.GetString(0),
                    reader.GetString(1),
                    reader.GetInt64(2),
                    reader.GetString(3)));
            }
        }

        var rates = new List<SourceSuccessRate>();
        using (var command = connection.CreateCommand())
        {
            command.CommandText =
                @"
                SELECT source_kind, count(*),
                       sum(CASE WHEN status = 'complete' THEN 1 ELSE 0 END)
                FROM collection_sources
                GROUP BY source_kind
                ORDER BY source_kind;
                ";
            using var reader = command.ExecuteReader();
            while (reader.Read())
            {
                rates.Add(new SourceSuccessRate(
                    reader.GetString(0),
                    reader.GetInt64(1),
                    reader.GetInt64(2)));
            }
        }

        return new HealthDetails(last, rates);
    }

    private static void InsertCollection(
        SqliteConnection connection,
        SqliteTransaction transaction,
        ClientObservationCollection collection)
    {
        using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText =
                @"
                INSERT INTO collections(
                    collection_id, site_id, started_at_ms, completed_at_ms,
                    history_hours, overall_status)
                VALUES($id, $site, $started, $completed, $hours, $status);
                ";
            command.Parameters.AddWithValue("$id", collection.CollectionId);
            command.Parameters.AddWithValue("$site", collection.SiteId);
            command.Parameters.AddWithValue("$started", ClientJournalValues.EpochMilliseconds(collection.StartedAt));
            command.Parameters.AddWithValue("$completed", ClientJournalValues.EpochMilliseconds(collection.CompletedAt));
            command.Parameters.AddWithValue("$hours", collection.HistoryHours);
            command.Parameters.AddWithValue("$status", ClientJournalValues.Status(collection.OverallStatus));
            command.ExecuteNonQuery();
        }

        InsertClientSource(connection, transaction, collection.CollectionId, collection.Connected);
        InsertClientSource(connection, transaction, collection.CollectionId, collection.History);
        InsertGroupSource(connection, transaction, collection.CollectionId, collection.Groups);
    }

    private static void InsertClientSource(
        SqliteConnection connection,
        SqliteTransaction transaction,
        string collectionId,
        SourceCollection<NormalizedClientObservation> source)
    {
        InsertSource(
            connection,
            transaction,
            collectionId,
            source.Source,
            source.Status,
            source.Records.Count,
            source.ErrorCode,
            source.ErrorMessage);

        foreach (var observation in source.Records
                     .OrderBy(value => value.MacAddress, StringComparer.Ordinal))
        {
            long observationId;
            using (var command = connection.CreateCommand())
            {
                command.Transaction = transaction;
                command.CommandText =
                    @"
                    INSERT INTO client_observations(
                        collection_id, source_kind, mac_address, client_name,
                        ip_address, observed_state, connected_at_ms, last_seen_at_ms)
                    VALUES($collection, $source, $mac, $name, $ip, $state, $connected, $last_seen);
                    SELECT last_insert_rowid();
                    ";
                command.Parameters.AddWithValue("$collection", collectionId);
                command.Parameters.AddWithValue("$source", ClientJournalValues.Source(source.Source));
                command.Parameters.AddWithValue("$mac", observation.MacAddress.ToLowerInvariant());
                command.Parameters.AddWithValue("$name", (object?)observation.Name ?? DBNull.Value);
                command.Parameters.AddWithValue("$ip", (object?)observation.IpAddress ?? DBNull.Value);
                command.Parameters.AddWithValue("$state", (object?)observation.State ?? DBNull.Value);
                command.Parameters.AddWithValue(
                    "$connected",
                    (object?)observation.ConnectedAtEpochMilliseconds ?? DBNull.Value);
                command.Parameters.AddWithValue(
                    "$last_seen",
                    (object?)observation.LastSeenEpochMilliseconds ?? DBNull.Value);
                observationId = Convert.ToInt64(
                    command.ExecuteScalar(),
                    CultureInfo.InvariantCulture);
            }

            foreach (var evidence in observation.Provenance
                         .OrderBy(value => value.FieldName, StringComparer.Ordinal))
            {
                using var command = connection.CreateCommand();
                command.Transaction = transaction;
                command.CommandText =
                    @"
                    INSERT INTO observation_field_provenance(
                        observation_id, field_name, source_field, authority, available)
                    VALUES($observation, $field, $source_field, $authority, $available);
                    ";
                command.Parameters.AddWithValue("$observation", observationId);
                command.Parameters.AddWithValue("$field", evidence.FieldName);
                command.Parameters.AddWithValue("$source_field", evidence.SourceField);
                command.Parameters.AddWithValue("$authority", evidence.Authority);
                command.Parameters.AddWithValue("$available", evidence.Available ? 1 : 0);
                command.ExecuteNonQuery();
            }
        }
    }

    private static void InsertGroupSource(
        SqliteConnection connection,
        SqliteTransaction transaction,
        string collectionId,
        SourceCollection<NormalizedClientGroup> source)
    {
        InsertSource(
            connection,
            transaction,
            collectionId,
            source.Source,
            source.Status,
            source.Records.Count,
            source.ErrorCode,
            source.ErrorMessage);

        foreach (var group in source.Records.OrderBy(value => value.GroupId, StringComparer.Ordinal))
        {
            using (var command = connection.CreateCommand())
            {
                command.Transaction = transaction;
                command.CommandText =
                    @"
                    INSERT INTO group_observations(collection_id, group_id, group_name)
                    VALUES($collection, $group, $name);
                    ";
                command.Parameters.AddWithValue("$collection", collectionId);
                command.Parameters.AddWithValue("$group", group.GroupId);
                command.Parameters.AddWithValue("$name", group.Name);
                command.ExecuteNonQuery();
            }

            foreach (var mac in group.Members.OrderBy(value => value, StringComparer.Ordinal))
            {
                using var command = connection.CreateCommand();
                command.Transaction = transaction;
                command.CommandText =
                    @"
                    INSERT INTO group_memberships(collection_id, group_id, mac_address)
                    VALUES($collection, $group, $mac);
                    ";
                command.Parameters.AddWithValue("$collection", collectionId);
                command.Parameters.AddWithValue("$group", group.GroupId);
                command.Parameters.AddWithValue("$mac", mac.ToLowerInvariant());
                command.ExecuteNonQuery();
            }
        }
    }

    private static void InsertSource(
        SqliteConnection connection,
        SqliteTransaction transaction,
        string collectionId,
        ClientObservationSource source,
        CollectionSourceStatus status,
        int recordCount,
        string? errorCode,
        string? errorMessage)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            @"
            INSERT INTO collection_sources(
                collection_id, source_kind, status, record_count, error_code, error_message)
            VALUES($collection, $source, $status, $count, $code, $message);
            ";
        command.Parameters.AddWithValue("$collection", collectionId);
        command.Parameters.AddWithValue("$source", ClientJournalValues.Source(source));
        command.Parameters.AddWithValue("$status", ClientJournalValues.Status(status));
        command.Parameters.AddWithValue("$count", recordCount);
        command.Parameters.AddWithValue("$code", (object?)errorCode ?? DBNull.Value);
        command.Parameters.AddWithValue("$message", (object?)errorMessage ?? DBNull.Value);
        command.ExecuteNonQuery();
    }

    private void PruneExpiredCollections(
        SqliteConnection connection,
        DateTimeOffset observedAt)
    {
        var cutoff = observedAt
            .AddDays(-_configuration.ClientJournalRetentionDays)
            .ToUnixTimeMilliseconds();
        using var command = connection.CreateCommand();
        command.CommandText =
            "DELETE FROM collections WHERE completed_at_ms < $cutoff;";
        command.Parameters.AddWithValue("$cutoff", cutoff);
        command.ExecuteNonQuery();
        using var vacuum = connection.CreateCommand();
        vacuum.CommandText = "PRAGMA incremental_vacuum(128);";
        vacuum.ExecuteNonQuery();
    }

    private void PruneForSize(SqliteConnection connection)
    {
        while (GetActiveBytes() > MaximumBytes)
        {
            using var command = connection.CreateCommand();
            command.CommandText =
                @"
                WITH protected AS (
                    SELECT collection_id
                    FROM (
                        SELECT c.collection_id,
                               row_number() OVER (
                                   PARTITION BY c.site_id, s.source_kind,
                                                CASE WHEN s.source_kind = 'uiHistory'
                                                     THEN c.history_hours ELSE 0 END
                                   ORDER BY c.completed_at_ms DESC, c.collection_id DESC
                               ) AS rank
                        FROM collections c
                        JOIN collection_sources s ON s.collection_id = c.collection_id
                        WHERE s.status = 'complete'
                    )
                    WHERE rank <= 2
                )
                DELETE FROM collections
                WHERE collection_id = (
                    SELECT collection_id
                    FROM collections
                    WHERE collection_id NOT IN (SELECT collection_id FROM protected)
                    ORDER BY completed_at_ms, collection_id
                    LIMIT 1
                );
                SELECT changes();
                ";
            var removed = Convert.ToInt32(command.ExecuteScalar(), CultureInfo.InvariantCulture);
            if (removed == 0)
            {
                using var fallback = connection.CreateCommand();
                fallback.CommandText =
                    @"
                    DELETE FROM collections
                    WHERE collection_id = (
                        SELECT collection_id FROM collections
                        ORDER BY completed_at_ms, collection_id
                        LIMIT 1
                    );
                    SELECT changes();
                    ";
                removed = Convert.ToInt32(
                    fallback.ExecuteScalar(),
                    CultureInfo.InvariantCulture);
            }

            if (removed == 0)
            {
                break;
            }

            Checkpoint(connection, truncate: true);
            using var vacuum = connection.CreateCommand();
            vacuum.CommandText = "PRAGMA incremental_vacuum(256);";
            vacuum.ExecuteNonQuery();
        }
    }

    private static IReadOnlyList<StoredClient> ReadClientSnapshot(
        SqliteConnection connection,
        string collectionId,
        string sourceKind)
    {
        using var command = connection.CreateCommand();
        command.CommandText =
            @"
            SELECT mac_address, client_name, ip_address, observed_state,
                   connected_at_ms, last_seen_at_ms
            FROM client_observations
            WHERE collection_id = $collection AND source_kind = $source
            ORDER BY mac_address;
            ";
        command.Parameters.AddWithValue("$collection", collectionId);
        command.Parameters.AddWithValue("$source", sourceKind);
        var clients = new List<StoredClient>();
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            clients.Add(new StoredClient(
                reader.GetString(0),
                reader.IsDBNull(1) ? null : reader.GetString(1),
                reader.IsDBNull(2) ? null : reader.GetString(2),
                reader.IsDBNull(3) ? null : reader.GetString(3),
                reader.IsDBNull(4) ? null : reader.GetInt64(4),
                reader.IsDBNull(5) ? null : reader.GetInt64(5)));
        }

        return clients;
    }

    private static IReadOnlyList<StoredGroup> ReadGroupSnapshot(
        SqliteConnection connection,
        string collectionId)
    {
        using var command = connection.CreateCommand();
        command.CommandText =
            @"
            SELECT g.group_id, g.group_name, m.mac_address
            FROM group_observations g
            LEFT JOIN group_memberships m
              ON m.collection_id = g.collection_id AND m.group_id = g.group_id
            WHERE g.collection_id = $collection
            ORDER BY g.group_id, m.mac_address;
            ";
        command.Parameters.AddWithValue("$collection", collectionId);
        var groups = new Dictionary<string, (string Name, List<string> Members)>(
            StringComparer.Ordinal);
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            var id = reader.GetString(0);
            if (!groups.TryGetValue(id, out var value))
            {
                value = (reader.GetString(1), new List<string>());
                groups.Add(id, value);
            }

            if (!reader.IsDBNull(2))
            {
                value.Members.Add(reader.GetString(2));
            }
        }

        return groups
            .Select(value => new StoredGroup(value.Key, value.Value.Name, value.Value.Members))
            .OrderBy(value => value.GroupId, StringComparer.Ordinal)
            .ToArray();
    }

    private static IReadOnlyList<FieldEvidence> ReadProvenance(
        SqliteConnection connection,
        long observationId)
    {
        using var command = connection.CreateCommand();
        command.CommandText =
            @"
            SELECT field_name, source_field, authority, available
            FROM observation_field_provenance
            WHERE observation_id = $observation
            ORDER BY field_name;
            ";
        command.Parameters.AddWithValue("$observation", observationId);
        var values = new List<FieldEvidence>();
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            values.Add(new FieldEvidence(
                reader.GetString(0),
                reader.GetString(1),
                reader.GetString(2),
                reader.GetInt32(3) == 1));
        }

        return values;
    }

    private void EnsureWritablePath()
    {
        if (OperatingSystem.IsWindows())
        {
            throw new ConfigurationException(
                "The client journal currently requires Unix filesystem permission semantics.");
        }

        var path = DatabasePath;
        var parent = Path.GetDirectoryName(path);
        if (string.IsNullOrWhiteSpace(parent))
        {
            throw new ConfigurationException(
                "UNIFI_CLIENT_JOURNAL_DB_PATH must have an absolute parent directory.");
        }

        if (!Directory.Exists(parent))
        {
            Directory.CreateDirectory(parent);
            SetDirectoryPrivate(parent);
        }

        ValidateNoSymlink(parent, isDirectory: true);
        var mode = File.GetUnixFileMode(parent);
        if ((mode & (UnixFileMode.GroupRead |
                     UnixFileMode.GroupWrite |
                     UnixFileMode.GroupExecute |
                     UnixFileMode.OtherRead |
                     UnixFileMode.OtherWrite |
                     UnixFileMode.OtherExecute)) != 0)
        {
            throw new ConfigurationException(
                "The client journal parent directory must be private (0700 or stricter).");
        }

        if (File.Exists(path))
        {
            ValidateNoSymlink(path, isDirectory: false);
        }
    }

    private void ValidateExistingPathForRead()
    {
        if (OperatingSystem.IsWindows())
        {
            throw new ConfigurationException(
                "The client journal currently requires Unix filesystem permission semantics.");
        }

        ValidateNoSymlink(DatabasePath, isDirectory: false);
        var parent = Path.GetDirectoryName(DatabasePath)!;
        ValidateNoSymlink(parent, isDirectory: true);
        var privateBits = UnixFileMode.GroupRead |
            UnixFileMode.GroupWrite |
            UnixFileMode.GroupExecute |
            UnixFileMode.OtherRead |
            UnixFileMode.OtherWrite |
            UnixFileMode.OtherExecute;
        if ((File.GetUnixFileMode(parent) & privateBits) != 0)
        {
            throw new ConfigurationException(
                "The client journal parent and active files must be private.");
        }

        foreach (var path in ActivePaths().Where(File.Exists))
        {
            if ((File.GetUnixFileMode(path) & privateBits) != 0)
            {
                throw new ConfigurationException(
                    "The client journal parent and active files must be private.");
            }
        }
    }

    private static void ValidateNoSymlink(string path, bool isDirectory)
    {
        FileSystemInfo info = isDirectory
            ? new DirectoryInfo(path)
            : new FileInfo(path);
        if (info.LinkTarget is not null ||
            (info.Attributes & FileAttributes.ReparsePoint) != 0)
        {
            throw new ConfigurationException(
                "The client journal path and its parent must not be symbolic links.");
        }
    }

    private void ApplyPrivateFileModes()
    {
        if (OperatingSystem.IsWindows())
        {
            throw new ConfigurationException(
                "The client journal currently requires Unix filesystem permission semantics.");
        }

        foreach (var path in ActivePaths().Where(File.Exists))
        {
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
    }

    private static void SetDirectoryPrivate(string path)
    {
        if (OperatingSystem.IsWindows())
        {
            throw new ConfigurationException(
                "The client journal currently requires Unix filesystem permission semantics.");
        }

        File.SetUnixFileMode(
            path,
            UnixFileMode.UserRead |
            UnixFileMode.UserWrite |
            UnixFileMode.UserExecute);
    }

    private IEnumerable<string> ActivePaths()
    {
        yield return DatabasePath;
        yield return DatabasePath + "-wal";
        yield return DatabasePath + "-shm";
    }

    private long GetActiveBytes() =>
        ActivePaths()
            .Where(File.Exists)
            .Sum(path => new FileInfo(path).Length);

    private QuarantineInventory GetQuarantineInventory()
    {
        var parent = Path.GetDirectoryName(DatabasePath);
        if (parent is null || !Directory.Exists(parent))
        {
            return new QuarantineInventory(0, 0);
        }

        var directories = Directory.EnumerateDirectories(
                parent,
                Path.GetFileName(DatabasePath) + ".quarantine-*",
                SearchOption.TopDirectoryOnly)
            .ToArray();
        var bytes = directories
            .SelectMany(path => Directory.EnumerateFiles(path))
            .Sum(path => new FileInfo(path).Length);
        return new QuarantineInventory(directories.Length, bytes);
    }

    private string CreateCorruptionFingerprint()
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        foreach (var path in ActivePaths())
        {
            var label = Encoding.UTF8.GetBytes(Path.GetFileName(path));
            hash.AppendData(label);
            if (!File.Exists(path))
            {
                hash.AppendData(new byte[] { 0 });
                continue;
            }

            var info = new FileInfo(path);
            hash.AppendData(BitConverter.GetBytes(info.Length));
            hash.AppendData(BitConverter.GetBytes(info.LastWriteTimeUtc.Ticks));
            using var stream = File.OpenRead(path);
            var buffer = new byte[64 * 1024];
            var read = stream.Read(buffer, 0, buffer.Length);
            hash.AppendData(buffer, 0, read);
        }

        return Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant();
    }

    private string GetNewQuarantineDirectory(string fingerprint) =>
        Path.Combine(
            Path.GetDirectoryName(DatabasePath)!,
            Path.GetFileName(DatabasePath) +
            ".quarantine-" +
            DateTimeOffset.UtcNow.ToString("yyyyMMddTHHmmssfffZ", CultureInfo.InvariantCulture) +
            "-" +
            fingerprint[..Math.Min(12, fingerprint.Length)]);

    private static bool IsDatabaseFailure(Exception exception) =>
        exception is SqliteException or
            InvalidDataException or
            ClientJournalMigrationException;

    private sealed record StoredCollectionBuilder(
        string CollectionId,
        string SiteId,
        long StartedAtMilliseconds,
        long CompletedAtMilliseconds,
        int HistoryHours,
        string OverallStatus)
    {
        public List<StoredSource> Sources { get; } = new();

        public StoredCollection Build() =>
            new(
                CollectionId,
                SiteId,
                StartedAtMilliseconds,
                CompletedAtMilliseconds,
                HistoryHours,
                OverallStatus,
                Sources);
    }

    private sealed record HealthDetails(
        IReadOnlyList<HealthCollection> LastCollections,
        IReadOnlyList<SourceSuccessRate> SourceSuccessRates);
}

public sealed record StoredCollection(
    string CollectionId,
    string SiteId,
    long StartedAtMilliseconds,
    long CompletedAtMilliseconds,
    int HistoryHours,
    string OverallStatus,
    IReadOnlyList<StoredSource> Sources);

public sealed record StoredSource(
    string SourceKind,
    string Status,
    int RecordCount,
    string? ErrorCode,
    string? ErrorMessage);

public sealed record StoredClient(
    string MacAddress,
    string? Name,
    string? IpAddress,
    string? State,
    long? ConnectedAtMilliseconds,
    long? LastSeenAtMilliseconds);

public sealed record StoredGroup(
    string GroupId,
    string Name,
    IReadOnlyList<string> Members);

public sealed record StoredSnapshot(
    IReadOnlyList<StoredClient> Clients,
    IReadOnlyList<StoredGroup> Groups);

public sealed record StoredClientHistoryRow(
    string CollectionId,
    string SiteId,
    long CompletedAtMilliseconds,
    int HistoryHours,
    string SourceKind,
    string SourceStatus,
    string? Name,
    string? IpAddress,
    string? State,
    long? ConnectedAtMilliseconds,
    long? LastSeenAtMilliseconds,
    IReadOnlyList<FieldEvidence> Provenance);

public sealed record HealthCollection(
    string CollectionId,
    string SiteId,
    long CompletedAtMilliseconds,
    string OverallStatus);

public sealed record SourceSuccessRate(
    string SourceKind,
    long CollectionCount,
    long CompleteCount);

public sealed record QuarantineInventory(int Count, long Bytes);

public sealed record JournalInspection(
    string State,
    int? SchemaVersion,
    int SupportedSchemaVersion,
    string? WalMode,
    int RetentionDays,
    int MaximumMib,
    long ActiveBytes,
    bool Oversized,
    string? CorruptionFingerprint,
    string? Reason,
    IReadOnlyList<HealthCollection> LastCollections,
    IReadOnlyList<SourceSuccessRate> SourceSuccessRates,
    QuarantineInventory Quarantine)
{
    public static JournalInspection Disabled(int retentionDays, int maximumMib) =>
        Empty("disabled", null, retentionDays, maximumMib);

    public static JournalInspection NotInitialized(
        int retentionDays,
        int maximumMib,
        QuarantineInventory quarantine) =>
        Empty("notInitialized", null, retentionDays, maximumMib) with
        {
            Quarantine = quarantine
        };

    public static JournalInspection Healthy(
        int schemaVersion,
        string walMode,
        int retentionDays,
        int maximumMib) =>
        Empty("healthy", schemaVersion, retentionDays, maximumMib) with
        {
            WalMode = walMode
        };

    public static JournalInspection MigrationRequired(
        int schemaVersion,
        int supportedSchemaVersion,
        int retentionDays,
        int maximumMib) =>
        Empty("migrationRequired", schemaVersion, retentionDays, maximumMib) with
        {
            SupportedSchemaVersion = supportedSchemaVersion
        };

    public static JournalInspection NewerSchema(
        int schemaVersion,
        int supportedSchemaVersion,
        int retentionDays,
        int maximumMib) =>
        Empty("newerSchemaNotSupported", schemaVersion, retentionDays, maximumMib) with
        {
            SupportedSchemaVersion = supportedSchemaVersion
        };

    public static JournalInspection Corrupt(
        string fingerprint,
        string reason,
        int retentionDays,
        int maximumMib,
        long activeBytes,
        QuarantineInventory quarantine) =>
        Empty("corrupt", null, retentionDays, maximumMib) with
        {
            CorruptionFingerprint = fingerprint,
            Reason = reason,
            ActiveBytes = activeBytes,
            Quarantine = quarantine
        };

    public static JournalInspection UnsafePath(
        string reason,
        int retentionDays,
        int maximumMib,
        long activeBytes,
        QuarantineInventory quarantine) =>
        Empty("unsafePath", null, retentionDays, maximumMib) with
        {
            Reason = reason,
            ActiveBytes = activeBytes,
            Quarantine = quarantine
        };

    private static JournalInspection Empty(
        string state,
        int? schemaVersion,
        int retentionDays,
        int maximumMib) =>
        new(
            state,
            schemaVersion,
            1,
            null,
            retentionDays,
            maximumMib,
            0,
            false,
            null,
            null,
            Array.Empty<HealthCollection>(),
            Array.Empty<SourceSuccessRate>(),
            new QuarantineInventory(0, 0));
}

public sealed class ClientJournalSizeException : Exception
{
    public ClientJournalSizeException(string message)
        : base(message)
    {
    }
}

public sealed class ClientJournalMigrationException : Exception
{
    public ClientJournalMigrationException(string message)
        : base(message)
    {
    }
}

public sealed class ClientJournalUnavailableException : Exception
{
    public ClientJournalUnavailableException(string message)
        : base(message)
    {
    }
}

public sealed class ClientJournalRecoveryException : Exception
{
    public ClientJournalRecoveryException(string message)
        : base(message)
    {
    }
}
