using System.ComponentModel.DataAnnotations;

namespace NSI.Api.Infrastructure.Identity.Entities;

public sealed class AuthAccount
{
    public Guid Id { get; set; } = Guid.NewGuid();

    public Guid UserId { get; set; }
    public User User { get; set; } = null!;

    [MaxLength(30)]
    public string Provider { get; set; } = null!; // "github"

    [MaxLength(128)]
    public string ProviderUserId { get; set; } = null!; // GitHub user id

    [MaxLength(100)]
    public string? ProviderUsername { get; set; } // GitHub login

    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
}