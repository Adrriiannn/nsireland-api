using Microsoft.EntityFrameworkCore;
using NSI.Api.Infrastructure.Identity.Entities;

namespace NSI.Api.Infrastructure.Data;

public sealed class AppDbContext : DbContext
{
    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }

    public DbSet<User> Users => Set<User>();
    public DbSet<AuthAccount> AuthAccounts => Set<AuthAccount>();
    public DbSet<Role> Roles => Set<Role>();
    public DbSet<Permission> Permissions => Set<Permission>();
    public DbSet<UserRole> UserRoles => Set<UserRole>();
    public DbSet<RolePermission> RolePermissions => Set<RolePermission>();
    public DbSet<RefreshToken> RefreshTokens => Set<RefreshToken>();
    public DbSet<SystemSetting> SystemSettings => Set<SystemSetting>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        // Composite keys for join tables
        modelBuilder.Entity<UserRole>().HasKey(x => new { x.UserId, x.RoleId });
        modelBuilder.Entity<RolePermission>().HasKey(x => new { x.RoleId, x.PermissionId });

        // Unique constraints
        modelBuilder.Entity<Role>()
            .HasIndex(x => x.Name).IsUnique();

        modelBuilder.Entity<Permission>()
            .HasIndex(x => x.Key).IsUnique();

        modelBuilder.Entity<AuthAccount>()
            .HasIndex(x => new { x.Provider, x.ProviderUserId })
            .IsUnique();

        modelBuilder.Entity<User>()
            .HasIndex(x => x.Email)
            .IsUnique()
            .HasFilter("[Email] IS NOT NULL"); // SQL Server filtered unique index

        modelBuilder.Entity<SystemSetting>().HasKey(x => x.Key);
    }
}