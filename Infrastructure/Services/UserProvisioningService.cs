using Microsoft.EntityFrameworkCore;
using NSI.Api.Infrastructure.Data;
using NSI.Api.Infrastructure.Identity.Entities;

namespace NSI.Api.Infrastructure.Identity.Services;

public sealed class UserProvisioningService
{
    private readonly AppDbContext _db;

    public UserProvisioningService(AppDbContext db) => _db = db;

    public async Task AssignDefaultRoleAsync(User user, CancellationToken ct = default)
    {
        using var tx = await _db.Database.BeginTransactionAsync(ct);

        var isFirstOwner = false;

        // Try claim ownership slot (unique key guarantees only one winner)
        var existing = await _db.SystemSettings
            .AsNoTracking()
            .SingleOrDefaultAsync(x => x.Key == "bootstrap.ownerUserId", ct);

        if (existing is null)
        {
            _db.SystemSettings.Add(new SystemSetting
            {
                Key = "bootstrap.ownerUserId",
                Value = user.Id.ToString()
            });

            try
            {
                await _db.SaveChangesAsync(ct);
                isFirstOwner = true;
            }
            catch (DbUpdateException)
            {
                isFirstOwner = false;
            }
        }

        var roleName = isFirstOwner ? "Owner" : "User";
        var role = await _db.Roles.SingleAsync(r => r.Name == roleName, ct);

        _db.UserRoles.Add(new UserRole { UserId = user.Id, RoleId = role.Id });

        await _db.SaveChangesAsync(ct);
        await tx.CommitAsync(ct);
    }
}