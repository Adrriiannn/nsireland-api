namespace NSI.Api.Features.Auth;

public sealed class GitHubTokenResponse
{
    public string? access_token { get; set; }
    public string? token_type { get; set; }
    public string? scope { get; set; }
}

public sealed class GitHubUserResponse
{
    public long id { get; set; }
    public string? login { get; set; }
    public string? name { get; set; }
    public string? avatar_url { get; set; }
    public string? email { get; set; }
}