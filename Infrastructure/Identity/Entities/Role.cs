using System.ComponentModel.DataAnnotations;

namespace NSI.Api.Infrastructure.Identity.Entities;

public sealed class Role
{
    public Guid Id { get; set; } = Guid.NewGuid();

    [MaxLength(50)]
    public string Name { get; set; } = null!; // Owner/Admin/User

    [MaxLength(200)]
    public string? Description { get; set; }

    public ICollection<UserRole> UserRoles { get; set; } = new List<UserRole>();
    public ICollection<RolePermission> RolePermissions { get; set; } = new List<RolePermission>();
}