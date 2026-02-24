using Microsoft.EntityFrameworkCore;
using NSI.Api.Infrastructure.Data;
using NSI.Api.Infrastructure.Identity.Entities;

namespace NSI.Api.Infrastructure.Identity;

public static class IdentitySeed
{
    public static async Task SeedAsync(AppDbContext db, CancellationToken ct = default)
    {
        // Ensure DB exists/migrated (for local dev this is fine; in prod we may handle differently later)
        await db.Database.MigrateAsync(ct);

        // Roles (minimal for now)
        var ownerRole = await GetOrCreateRole(db, "Owner", "Full platform access", ct);
        var adminRole = await GetOrCreateRole(db, "Admin", "Administrative access", ct);
        var userRole  = await GetOrCreateRole(db, "User",  "Standard user", ct);

        // Permissions (ACP + Editors + users/roles management + basic system reads)
        var permissions = new (string Key, string? Description)[]
        {
            ("acp.access", "Access the admin control panel"),
            ("editor.web.access", "Access the web editor"),
            ("editor.code.access", "Access the code editor"),

            ("users.read", "Read users"),
            ("users.write", "Create/update users"),
            ("users.disable", "Disable users"),

            ("roles.read", "Read roles"),
            ("roles.write", "Create/update roles"),

            ("permissions.read", "Read permissions"),
            ("permissions.write", "Create/update permissions"),

            ("audit.read", "Read audit logs"),

            ("system.health.read", "Read system health"),
            ("system.metrics.read", "Read system metrics"),
        };

        var permissionEntities = new List<Permission>();
        foreach (var (key, desc) in permissions)
        {
            var p = await db.Permissions.FirstOrDefaultAsync(x => x.Key == key, ct);
            if (p is null)
            {
                p = new Permission { Key = key, Description = desc };
                db.Permissions.Add(p);
            }
            else if (p.Description != desc)
            {
                p.Description = desc;
            }

            permissionEntities.Add(p);
        }

        await db.SaveChangesAsync(ct);

        // Owner gets all permissions
        await EnsureRoleHasPermissions(db, ownerRole.Id, permissionEntities.Select(p => p.Id), ct);

        // Admin gets most permissions (you can tweak later)
        await EnsureRoleHasPermissions(db, adminRole.Id, permissionEntities.Select(p => p.Id), ct);

        // User gets none of these by default (keeps tools private)
        // (Later you'll add public-facing permissions as needed)
    }

    private static async Task<Role> GetOrCreateRole(AppDbContext db, string name, string? description, CancellationToken ct)
    {
        var role = await db.Roles.FirstOrDefaultAsync(r => r.Name == name, ct);
        if (role is null)
        {
            role = new Role { Name = name, Description = description };
            db.Roles.Add(role);
            await db.SaveChangesAsync(ct);
        }
        else if (role.Description != description)
        {
            role.Description = description;
            await db.SaveChangesAsync(ct);
        }

        return role;
    }

    private static async Task EnsureRoleHasPermissions(
        AppDbContext db,
        Guid roleId,
        IEnumerable<Guid> permissionIds,
        CancellationToken ct)
    {
        var existing = await db.RolePermissions
            .Where(rp => rp.RoleId == roleId)
            .Select(rp => rp.PermissionId)
            .ToListAsync(ct);

        var toAdd = permissionIds.Except(existing).ToList();
        if (toAdd.Count == 0) return;

        foreach (var pid in toAdd)
        {
            db.RolePermissions.Add(new RolePermission { RoleId = roleId, PermissionId = pid });
        }

        await db.SaveChangesAsync(ct);
    }
}