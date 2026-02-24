using System.ComponentModel.DataAnnotations;

namespace NSI.Api.Infrastructure.Identity.Entities;

public sealed class RefreshToken
{
    public Guid Id { get; set; } = Guid.NewGuid();

    public Guid UserId { get; set; }
    public User User { get; set; } = null!;

    // Store ONLY the hash (never store the raw token)
    [MaxLength(256)]
    public string TokenHash { get; set; } = null!;

    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset ExpiresAt { get; set; }

    public DateTimeOffset? RevokedAt { get; set; }

    public Guid? ReplacedByTokenId { get; set; }

    [MaxLength(512)]
    public string? UserAgent { get; set; }

    [MaxLength(64)]
    public string? IpAddress { get; set; }
}