namespace NSI.Api.Features.Auth;

public sealed class RegisterRequest
{
    public string Email { get; set; } = null!;
    public string Password { get; set; } = null!;
    public string? DisplayName { get; set; }
}