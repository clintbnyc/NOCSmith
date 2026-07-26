using System.Text.Json.Nodes;
using UnifiMcp.Security;

namespace UnifiMcp.Tests;

public sealed class SecretRedactorTests
{
    [Fact]
    public void Redacts_sensitive_properties_and_known_values_recursively()
    {
        var redactor = new SecretRedactor("actual-api-key");
        var source = new JsonObject
        {
            ["name"] = "Office",
            ["password"] = "wifi-secret",
            ["nested"] = new JsonObject
            {
                ["apiKey"] = "actual-api-key",
                ["message"] = "Authorization: Bearer abc.def"
            }
        };

        var result = redactor.Redact(source)!;

        Assert.Equal("Office", result["name"]!.GetValue<string>());
        Assert.Equal("<redacted>", result["password"]!.GetValue<string>());
        Assert.Equal("<redacted>", result["nested"]!["apiKey"]!.GetValue<string>());
        Assert.DoesNotContain("abc.def", result.ToJsonString(), StringComparison.Ordinal);
        Assert.DoesNotContain("actual-api-key", result.ToJsonString(), StringComparison.Ordinal);
    }

    [Fact]
    public void Redacts_both_local_and_site_manager_keys()
    {
        var redactor = new SecretRedactor("local-key", "site-manager-key");

        var result = redactor.Redact(
            "local=local-key cloud=site-manager-key");

        Assert.DoesNotContain("local-key", result, StringComparison.Ordinal);
        Assert.DoesNotContain("site-manager-key", result, StringComparison.Ordinal);
        Assert.Equal("local=<redacted> cloud=<redacted>", result);
    }

    [Fact]
    public void Redacts_hotspot_voucher_codes_without_hiding_unrelated_codes()
    {
        var redactor = new SecretRedactor();
        var source = new JsonObject
        {
            ["country"] = new JsonObject { ["code"] = "US", ["name"] = "United States" },
            ["voucher"] = new JsonObject
            {
                ["id"] = "00000000-0000-0000-0000-000000000001",
                ["code"] = "4861409510",
                ["timeLimitMinutes"] = 60
            }
        };

        var result = redactor.Redact(source)!;

        Assert.Equal("US", result["country"]!["code"]!.GetValue<string>());
        Assert.Equal("<redacted>", result["voucher"]!["code"]!.GetValue<string>());
    }

    [Fact]
    public void Redacts_filter_values_from_displayed_request_targets()
    {
        var redactor = new SecretRedactor();

        var result = redactor.RedactRequestTarget(
            "/v1/sites/site/hotspot/vouchers?filter=code.eq%28%274861409510%27%29&force=true");

        Assert.DoesNotContain("4861409510", result, StringComparison.Ordinal);
        Assert.Contains("filter=%3Credacted%3E", result, StringComparison.Ordinal);
        Assert.Contains("force=true", result, StringComparison.Ordinal);
    }

    [Fact]
    public void Redacts_credentials_embedded_in_notes_and_comments()
    {
        var redactor = new SecretRedactor();
        var text = "Rack note; password=hunter2 token: abc123 JSON={\"psk\":\"wifi-secret\"}\n-----BEGIN PRIVATE KEY-----\nprivate-material\n-----END PRIVATE KEY-----";

        var result = redactor.Redact(text);

        Assert.Contains("Rack note", result, StringComparison.Ordinal);
        Assert.DoesNotContain("hunter2", result, StringComparison.Ordinal);
        Assert.DoesNotContain("abc123", result, StringComparison.Ordinal);
        Assert.DoesNotContain("wifi-secret", result, StringComparison.Ordinal);
        Assert.DoesNotContain("private-material", result, StringComparison.Ordinal);
        Assert.Contains("password=<redacted>", result, StringComparison.Ordinal);
        Assert.Contains("token: <redacted>", result, StringComparison.Ordinal);
    }
}
