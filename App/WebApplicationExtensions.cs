namespace NSI.Api.App;

public static class WebApplicationExtensions
{
    public static WebApplication MapApp(this WebApplication app)
    {
        // Health & diagnostics
        app.MapGet("/health", () => Results.Ok(new { status = "ok", service = "nsi-api" }));

        // Modules (features)
        app.MapModules();

        return app;
    }

    private static WebApplication MapModules(this WebApplication app)
    {
        // We’ll add modules here in the next commits, e.g.:
        // app.MapAssetsModule();

        return app;
    }
}