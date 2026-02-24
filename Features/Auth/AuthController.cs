using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Hosting;
using System.Security.Claims;
using NSI.Api.Infrastructure.Data;
using NSI.Api.Infrastructure.Identity.Entities;
using NSI.Api.Infrastructure.Identity.Services;

namespace NSI.Api.Features.Auth;

[ApiController]
[Route("auth")]
public sealed class AuthController : ControllerBase
{
    private readonly AppDbContext _db;
    private readonly PasswordHasher _hasher;
    private readonly UserProvisioningService _provisioning;
    private readonly TokenService _tokens;

    public AuthController(
        AppDbContext db,
        PasswordHasher hasher,
        UserProvisioningService provisioning,
        TokenService tokens)
    {
        _db = db;
        _hasher = hasher;
        _provisioning = provisioning;
        _tokens = tokens;
    }

    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterRequest req, CancellationToken ct)
    {
        var email = req.Email.Trim().ToLowerInvariant();

        if (string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(req.Password))
            return BadRequest(new { error = "Email and password are required." });

        if (req.Password.Length < 10)
            return BadRequest(new { error = "Password must be at least 10 characters." });

        var exists = await _db.Users.AnyAsync(u => u.Email == email, ct);
        if (exists)
            return Conflict(new { error = "Email is already registered." });

        var user = new User
        {
            Email = email,
            DisplayName = req.DisplayName?.Trim()
        };

        user.PasswordHash = await _hasher.HashAsync(req.Password, ct);

        _db.Users.Add(user);
        await _db.SaveChangesAsync(ct);

        // Assign Owner if first user, else User
        await _provisioning.AssignDefaultRoleAsync(user, ct);

        // Issue tokens
        var access = await _tokens.CreateAccessToken(user, ct);
        var (rawRefresh, _) = await _tokens.CreateRefreshTokenAsync(
            user,
            Request.Headers.UserAgent.ToString(),
            HttpContext.Connection.RemoteIpAddress?.ToString(),
            ct
        );

        var isDev = HttpContext.RequestServices.GetRequiredService<IHostEnvironment>().IsDevelopment();
        _tokens.SetRefreshCookie(Response, rawRefresh, isDev);

        return Ok(new
        {
            accessToken = access,
            user = new { id = user.Id, email = user.Email, displayName = user.DisplayName }
        });
    }

    [Authorize]
    [HttpGet("me")]
    public async Task<IActionResult> Me(CancellationToken ct)
    {
        var userIdStr = User.FindFirstValue("uid") ?? User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (string.IsNullOrWhiteSpace(userIdStr) || !Guid.TryParse(userIdStr, out var userId))
            return Unauthorized();

        var user = await _db.Users
            .AsNoTracking()
            .Where(u => u.Id == userId)
            .Select(u => new
            {
                u.Id,
                u.Email,
                u.DisplayName,
                u.Username,
                u.AvatarUrl,
                u.CreatedAt,
                u.LastLoginAt
            })
            .FirstOrDefaultAsync(ct);

        if (user is null)
            return Unauthorized();

        var roles = await _db.UserRoles
            .AsNoTracking()
            .Where(ur => ur.UserId == userId)
            .Select(ur => ur.Role.Name)
            .ToListAsync(ct);

        var permissions = await _db.UserRoles
            .AsNoTracking()
            .Where(ur => ur.UserId == userId)
            .SelectMany(ur => ur.Role.RolePermissions.Select(rp => rp.Permission.Key))
            .Distinct()
            .ToListAsync(ct);

        return Ok(new
        {
            user,
            roles,
            permissions
        });
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginRequest req, CancellationToken ct)
    {
        var email = req.Email.Trim().ToLowerInvariant();

        var user = await _db.Users.FirstOrDefaultAsync(u => u.Email == email, ct);
        if (user is null || user.PasswordHash is null)
            return Unauthorized(new { error = "Invalid email or password." });

        var ok = await _hasher.VerifyAsync(req.Password, user.PasswordHash, ct);
        if (!ok)
            return Unauthorized(new { error = "Invalid email or password." });

        user.LastLoginAt = DateTimeOffset.UtcNow;
        await _db.SaveChangesAsync(ct);

        var access = await _tokens.CreateAccessToken(user, ct);
        var (rawRefresh, _) = await _tokens.CreateRefreshTokenAsync(
            user,
            Request.Headers.UserAgent.ToString(),
            HttpContext.Connection.RemoteIpAddress?.ToString(),
            ct
        );

        var isDev = HttpContext.RequestServices.GetRequiredService<IHostEnvironment>().IsDevelopment();
        _tokens.SetRefreshCookie(Response, rawRefresh, isDev);

        return Ok(new
        {
            accessToken = access,
            user = new { id = user.Id, email = user.Email, displayName = user.DisplayName }
        });
    }

    [HttpPost("refresh")]
    public async Task<IActionResult> Refresh(CancellationToken ct)
    {
        if (!Request.Cookies.TryGetValue("nsi_refresh", out var raw) || string.IsNullOrWhiteSpace(raw))
            return Unauthorized(new { error = "Missing refresh token." });

        var hash = TokenService.HashRefreshToken(raw);

        var rt = await _db.RefreshTokens
            .FirstOrDefaultAsync(x =>
                x.TokenHash == hash &&
                x.RevokedAt == null &&
                x.ExpiresAt > DateTimeOffset.UtcNow,
                ct);

        if (rt is null)
            return Unauthorized(new { error = "Invalid refresh token." });

        var user = await _db.Users.FirstOrDefaultAsync(u => u.Id == rt.UserId, ct);
        if (user is null)
            return Unauthorized(new { error = "User not found." });

        // Rotate refresh token: revoke old, issue new
        rt.RevokedAt = DateTimeOffset.UtcNow;

        var (newRaw, newEntity) = await _tokens.CreateRefreshTokenAsync(
            user,
            Request.Headers.UserAgent.ToString(),
            HttpContext.Connection.RemoteIpAddress?.ToString(),
            ct
        );

        rt.ReplacedByTokenId = newEntity.Id;
        await _db.SaveChangesAsync(ct);

        var access = await _tokens.CreateAccessToken(user, ct);

        var isDev = HttpContext.RequestServices.GetRequiredService<IHostEnvironment>().IsDevelopment();
        _tokens.SetRefreshCookie(Response, newRaw, isDev);

        return Ok(new { accessToken = access });
    }

    [Authorize(Policy = "RequireAcpAccess")]
    [HttpGet("acp-test")]
    public IActionResult AcpTest()
    {
        return Ok(new { message = "ACP access granted." });
    }
}