using System.ComponentModel.DataAnnotations;

namespace NSI.Api.Infrastructure.Identity.Entities;

public sealed class User
{
    public Guid Id { get; set; } = Guid.NewGuid();

    // Email is optional if user signs up via GitHub-only initially
    [MaxLength(320)]
    public string? Email { get; set; }

    [MaxLength(100)]
    public string? DisplayName { get; set; }

    [MaxLength(50)]
    public string? Username { get; set; }

    [MaxLength(2048)]
    public string? AvatarUrl { get; set; }

    // Email/password users will have this; OAuth-only users can have null
    public string? PasswordHash { get; set; }

    [MaxLength(20)]
    public string Status { get; set; } = UserStatus.Active;

    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset? LastLoginAt { get; set; }

    public ICollection<UserRole> UserRoles { get; set; } = new List<UserRole>();
    public ICollection<AuthAccount> AuthAccounts { get; set; } = new List<AuthAccount>();
    public ICollection<RefreshToken> RefreshTokens { get; set; } = new List<RefreshToken>();
}

public static class UserStatus
{
    public const string Active = "active";
    public const string Disabled = "disabled";
    public const string Blocked = "blocked";
}