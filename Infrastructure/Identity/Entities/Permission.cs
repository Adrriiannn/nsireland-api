using System.ComponentModel.DataAnnotations;

namespace NSI.Api.Infrastructure.Identity.Entities;

public sealed class Permission
{
    public Guid Id { get; set; } = Guid.NewGuid();

    // e.g. "acp.access", "users.read"
    [MaxLength(100)]
    public string Key { get; set; } = null!;

    [MaxLength(200)]
    public string? Description { get; set; }

    public ICollection<RolePermission> RolePermissions { get; set; } = new List<RolePermission>();
}