using Microsoft.Extensions.Options;

namespace NSI.Api.Infrastructure.Storage;

public static class BlobStorageExtensions
{
    public static IServiceCollection AddBlobStorage(this IServiceCollection services, IConfiguration config)
    {
        services.AddOptions<BlobStorageOptions>()
            .Configure(options =>
            {
                options.AccountName = config["Storage:AccountName"] ?? "";
                options.ConnectionString = config["Storage:ConnectionString"];

                options.Containers = new BlobStorageOptions.ContainerOptions
                {
                    PublicAssets = config["Storage:Containers:PublicAssets"] ?? "public-assets",
                    PrivateUploads = config["Storage:Containers:PrivateUploads"] ?? "private-uploads",
                    EditorMedia = config["Storage:Containers:EditorMedia"] ?? "editor-media",
                };
            });

        services.AddSingleton<IBlobStorageService, BlobStorageService>();

        return services;
    }
}