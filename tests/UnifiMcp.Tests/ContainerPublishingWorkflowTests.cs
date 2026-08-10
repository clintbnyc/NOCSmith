using System.Text.RegularExpressions;

namespace UnifiMcp.Tests;

public sealed class ContainerPublishingWorkflowTests
{
    private static readonly Regex ActionReferencePattern = new(
        @"(?m)^\s*uses:\s*[^@\s]+@(?<revision>[^\s#]+)",
        RegexOptions.CultureInvariant);

    [Fact]
    public void Ghcr_workflow_preserves_the_reviewed_release_boundary()
    {
        var workflow = File.ReadAllText(FindRepositoryFile(
            ".github",
            "workflows",
            "publish-container.yml"));

        Assert.Contains("  release:\n    types: [published]\n", workflow);
        Assert.Contains("  workflow_dispatch:\n", workflow);
        Assert.DoesNotMatch(
            new Regex(
                @"(?m)^  (push|pull_request|pull_request_target|workflow_run):",
                RegexOptions.CultureInvariant),
            workflow);
        Assert.Contains(
            "if: github.event_name == 'workflow_dispatch' || " +
            "github.event.release.prerelease == false",
            workflow);
        Assert.Contains("timeout-minutes: 45", workflow);

        Assert.Contains("permissions:\n  contents: read\n  packages: write\n", workflow);
        Assert.DoesNotContain("contents: write", workflow);
        Assert.DoesNotContain("id-token:", workflow);
        Assert.DoesNotContain("attestations:", workflow);
        Assert.DoesNotContain("pull_request", workflow);

        var actionReferences = ActionReferencePattern.Matches(workflow);
        Assert.Equal(7, actionReferences.Count);
        Assert.All(
            actionReferences.Cast<Match>(),
            match => Assert.Matches("^[0-9a-f]{40}$", match.Groups["revision"].Value));

        Assert.Contains("^v?[0-9]+\\.[0-9]+\\.[0-9]+$", workflow);
        Assert.Contains("git merge-base --is-ancestor", workflow);
        Assert.Contains("dotnet restore UnifiMcp.slnx --locked-mode", workflow);
        Assert.Contains("dotnet format UnifiMcp.slnx --no-restore --verify-no-changes", workflow);
        Assert.Contains("dotnet test UnifiMcp.slnx --configuration Release --no-restore", workflow);
        Assert.Contains("git diff --check", workflow);

        Assert.Contains("type=sha,format=long,prefix=sha-", workflow);
        Assert.Contains(
            "type=semver,pattern={{version}},value=${{ github.event.release.tag_name }}," +
            "enable=${{ github.event_name == 'release' }}",
            workflow);
        Assert.Contains(
            "type=raw,value=latest,enable=${{ github.event_name == 'release' }}",
            workflow);
        Assert.Contains("platforms: linux/amd64,linux/arm64", workflow);
        Assert.Contains("provenance: mode=max", workflow);
        Assert.Contains(
            "sbom: generator=docker/buildkit-syft-scanner@sha256:" +
            "79e7b013cbec16bbb436f312819a49a4a57752b2270c1a9332ae1a10fcc82a68",
            workflow);
        Assert.Contains(
            "tonistiigi/binfmt@sha256:400a4873b838d1b89194d982c45e5fb3cda4593fbfd7e08a02e76b03b21166f0",
            workflow);
        Assert.Contains(
            "moby/buildkit:buildx-stable-1@sha256:" +
            "2f5adac4ecd194d9f8c10b7b5d7bceb5186853db1b26e5abd3a657af0b7e26ec",
            workflow);
        Assert.Contains("docker buildx imagetools inspect", workflow);
    }

    private static string FindRepositoryFile(params string[] segments)
    {
        for (var directory = new DirectoryInfo(AppContext.BaseDirectory);
             directory is not null;
             directory = directory.Parent)
        {
            if (!File.Exists(Path.Combine(directory.FullName, "UnifiMcp.slnx")))
            {
                continue;
            }

            return Path.Combine(new[] { directory.FullName }.Concat(segments).ToArray());
        }

        throw new DirectoryNotFoundException("Could not locate the repository root.");
    }
}
