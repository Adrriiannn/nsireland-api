using Microsoft.Extensions.Options;
using NSI.Api.Infrastructure.Storage;

namespace NSI.Api.Features.Assets;

public static class UploadPublicAssetEndpoint
{
    public static RouteHandlerBuilder MapUploadPublicAsset(this RouteGroupBuilder group)
    {
        return group.MapPost("/upload/public", async (
                HttpRequest request,
                IBlobStorageService storage,
                IOptions<BlobStorageOptions> options,
                CancellationToken ct) =>
            {
                if (!request.HasFormContentType)
                    return Results.BadRequest("Expected multipart/form-data");

                var form = await request.ReadFormAsync(ct);
                var file = form.Files.GetFile("file");

                if (file is null || file.Length == 0)
                    return Results.BadRequest("Missing form file field named 'file'");

                var safeFileName = Path.GetFileName(file.FileName);
                var blobName = $"{DateTime.UtcNow:yyyyMMdd}/{Guid.NewGuid():N}_{safeFileName}";
                var containerName = options.Value.Containers.PublicAssets;

                await using var stream = file.OpenReadStream();
                var url = await storage.UploadAsync(containerName, blobName, stream, file.ContentType, ct);

                return Results.Ok(new
                {
                    fileName = safeFileName,
                    blobName,
                    url = url.ToString()
                });
            })
            .DisableAntiforgery();
    }
}