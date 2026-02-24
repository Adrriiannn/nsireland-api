namespace NSI.Api.Infrastructure.Storage;

public sealed class BlobStorageOptions
{
    public string AccountName { get; set; } = "";
    public ContainerOptions Containers { get; set; } = new();

    public sealed class ContainerOptions
    {
        public string PublicAssets { get; set; } = "public-assets";
        public string PrivateUploads { get; set; } = "private-uploads";
        public string EditorMedia { get; set; } = "editor-media";
    }
}