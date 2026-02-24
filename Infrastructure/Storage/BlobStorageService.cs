using Azure.Identity;
using Azure.Storage.Blobs;
using Azure.Storage.Blobs.Models;
using Microsoft.Extensions.Options;

namespace NSI.Api.Infrastructure.Storage;

public interface IBlobStorageService
{
    Task<Uri> UploadAsync(
        string containerName,
        string blobName,
        Stream content,
        string contentType,
        CancellationToken ct = default);
}

internal sealed class BlobStorageService : IBlobStorageService
{
    private readonly BlobServiceClient _blobService;

    public BlobStorageService(IOptions<BlobStorageOptions> options)
    {
        var cs = options.Value.ConnectionString;

        if (!string.IsNullOrWhiteSpace(cs))
        {
            _blobService = new BlobServiceClient(cs);
            return;
        }

        var accountName = options.Value.AccountName;

        if (string.IsNullOrWhiteSpace(accountName))
            throw new InvalidOperationException(
                "Storage settings missing. Set Storage:AccountName (Azure) or Storage:ConnectionString (local).");

        var serviceUri = new Uri($"https://{accountName}.blob.core.windows.net");
        _blobService = new BlobServiceClient(serviceUri, new DefaultAzureCredential());
    }

    public async Task<Uri> UploadAsync(
        string containerName,
        string blobName,
        Stream content,
        string contentType,
        CancellationToken ct = default)
    {
        var container = _blobService.GetBlobContainerClient(containerName);
        var blob = container.GetBlobClient(blobName);

        await blob.UploadAsync(content, overwrite: false, cancellationToken: ct);

        // Nice-to-have for browser rendering
        await blob.SetHttpHeadersAsync(
            new BlobHttpHeaders { ContentType = contentType },
            cancellationToken: ct);

        return blob.Uri;
    }
}