using System.Net;

namespace UnifiMcp.Api;

public sealed class UnifiApiException : Exception
{
    public UnifiApiException(HttpStatusCode statusCode, string message)
        : base(message)
    {
        StatusCode = statusCode;
    }

    public HttpStatusCode StatusCode { get; }
}
