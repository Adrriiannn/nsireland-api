namespace NSI.Api.Features.Assets;

public static class AssetsModule
{
    public static WebApplication MapAssetsModule(this WebApplication app)
    {
        var group = app.MapGroup("/api/v1/assets")
            .WithTags("Assets");

        group.MapUploadPublicAsset();

        return app;
    }
}