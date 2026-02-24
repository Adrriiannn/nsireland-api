using Azure.Identity;
using Azure.Storage.Blobs;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddOpenApi();

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

// In Azure, HTTPS is already handled by App Service.
// If you want to keep redirection locally, you can, but it's optional.
// app.UseHttpsRedirection();

app.MapGet("/health", () => Results.Ok(new { status = "ok", service = "nsi-api" }));

// ---- Blob upload endpoint (public-assets) ----
// POST /api/v1/assets/upload/public
// form-data: file=<yourfile>
app.MapPost("/api/v1/assets/upload/public", async (HttpRequest request, IConfiguration config) =>
{
    if (!request.HasFormContentType)
        return Results.BadRequest("Expected multipart/form-data");

    var form = await request.ReadFormAsync();
    var file = form.Files.GetFile("file");

    if (file is null || file.Length == 0)
        return Results.BadRequest("Missing form file field named 'file'");

    var accountName = config["Storage:AccountName"];
    var containerName = config["Storage:Containers:PublicAssets"];

    if (string.IsNullOrWhiteSpace(accountName) || string.IsNullOrWhiteSpace(containerName))
        return Results.Problem("Storage settings missing. Check App Service env vars: Storage__AccountName and Storage__Containers__PublicAssets");

    // Uses Managed Identity in Azure automatically, and your dev identity locally (Visual Studio/Azure CLI login)
    var credential = new DefaultAzureCredential();
    var serviceUri = new Uri($"https://{accountName}.blob.core.windows.net");
    var blobService = new BlobServiceClient(serviceUri, credential);

    var container = blobService.GetBlobContainerClient(containerName);

    // unique blob name
    var safeFileName = Path.GetFileName(file.FileName);
    var blobName = $"{DateTime.UtcNow:yyyyMMdd}/{Guid.NewGuid():N}_{safeFileName}";
    var blob = container.GetBlobClient(blobName);

    await using var stream = file.OpenReadStream();
    await blob.UploadAsync(stream, overwrite: false);

    // Public container: blob.Uri is directly accessible
    return Results.Ok(new
    {
        fileName = safeFileName,
        blobName,
        url = blob.Uri.ToString()
    });
})
.DisableAntiforgery(); // allows simple form posts without antiforgery token

app.Run();