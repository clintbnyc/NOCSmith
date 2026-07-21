using System.Net;

namespace UnifiMcp.Api;

public sealed class UnifiApiException : Exception
{
    public UnifiApiException(HttpStatusCode statusCode, string message, string? code = null)
        : base(message)
    {
        StatusCode = statusCode;
        Code = code;
    }

    public HttpStatusCode StatusCode { get; }

    public string? Code { get; }
}
