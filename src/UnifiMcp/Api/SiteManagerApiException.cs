using System.Net;

namespace UnifiMcp.Api;

public sealed class SiteManagerApiException : Exception
{
    public SiteManagerApiException(
        HttpStatusCode statusCode,
        string message,
        string? code = null,
        DateTimeOffset? retryAt = null)
        : base(message)
    {
        StatusCode = statusCode;
        Code = code;
        RetryAt = retryAt;
    }

    public HttpStatusCode StatusCode { get; }

    public string? Code { get; }

    public DateTimeOffset? RetryAt { get; }

    public bool IsRateLimited => StatusCode == HttpStatusCode.TooManyRequests;
}
