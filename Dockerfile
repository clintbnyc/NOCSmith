FROM mcr.microsoft.com/dotnet/sdk:10.0.302-noble@sha256:ed034a8bf0b24ded0cbbac07e17825d8e9ebfe21e308191d0f7421eaf5ad4664 AS build

WORKDIR /source
COPY Directory.Build.props global.json ./
COPY src/UnifiMcp/UnifiMcp.csproj src/UnifiMcp/packages.lock.json src/UnifiMcp/
RUN dotnet restore src/UnifiMcp/UnifiMcp.csproj --locked-mode

COPY contracts/ contracts/
COPY src/UnifiMcp/ src/UnifiMcp/
RUN dotnet publish src/UnifiMcp/UnifiMcp.csproj \
    --configuration Release \
    --no-restore \
    --output /app \
    /p:UseAppHost=false

FROM mcr.microsoft.com/dotnet/aspnet:10.0.10-noble-chiseled-extra@sha256:f9bd6be9b5ab75b8196bff0f0972580edaea7fa8ca04e6ef530950e33caee5b0

LABEL org.opencontainers.image.source="https://github.com/Webbman-nyc/unifi-mcp"
LABEL org.opencontainers.image.title="NOCsmith by Clint"
LABEL org.opencontainers.image.description="Network intelligence, forged safely."

WORKDIR /app
COPY --from=build --chown=$APP_UID:$APP_UID /app/ ./

USER $APP_UID
ENTRYPOINT ["dotnet", "/app/unifi-mcp.dll"]
CMD ["serve-http"]
