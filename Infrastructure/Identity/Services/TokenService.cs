using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Microsoft.EntityFrameworkCore;
using NSI.Api.Infrastructure.Data;
using NSI.Api.Infrastructure.Identity.Entities;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace NSI.Api.Infrastructure.Identity.Services;

public sealed class TokenService
{
    private readonly AppDbContext _db;
    private readonly IConfiguration _config;

    public TokenService(AppDbContext db, IConfiguration config)
    {
        _db = db;
        _config = config;
    }

    public async Task<string> CreateAccessToken(User user, CancellationToken ct = default)
    {
        var issuer = _config["Auth:JwtIssuer"]!;
        var audience = _config["Auth:JwtAudience"]!;
        var key = _config["Auth:JwtSigningKey"]!;

        var signingKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key));
        var creds = new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha256);

        var roles = await _db.UserRoles
            .Where(ur => ur.UserId == user.Id)
            .Select(ur => ur.Role.Name)
            .ToListAsync(ct);

        var permissions = await _db.UserRoles
            .Where(ur => ur.UserId == user.Id)
            .SelectMany(ur => ur.Role.RolePermissions.Select(rp => rp.Permission.Key))
            .Distinct()
            .ToListAsync(ct);

        var claims = new List<Claim>
        {
            new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
            new Claim("uid", user.Id.ToString())
        };

        foreach (var role in roles)
            claims.Add(new Claim(ClaimTypes.Role, role));

        foreach (var perm in permissions)
            claims.Add(new Claim("perm", perm));

        var minutes = int.Parse(_config["Auth:AccessTokenMinutes"] ?? "10");

        var token = new JwtSecurityToken(
            issuer: issuer,
            audience: audience,
            claims: claims,
            expires: DateTime.UtcNow.AddMinutes(minutes),
            signingCredentials: creds
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    public async Task<(string RawToken, RefreshToken Entity)> CreateRefreshTokenAsync(User user, string? userAgent, string? ip, CancellationToken ct = default)
    {
        var days = int.Parse(_config["Auth:RefreshTokenDays"] ?? "14");

        var raw = Convert.ToBase64String(RandomNumberGenerator.GetBytes(48)); // raw token
        var hash = HashToken(raw);

        var rt = new RefreshToken
        {
            UserId = user.Id,
            TokenHash = hash,
            ExpiresAt = DateTimeOffset.UtcNow.AddDays(days),
            UserAgent = userAgent,
            IpAddress = ip
        };

        _db.RefreshTokens.Add(rt);
        await _db.SaveChangesAsync(ct);

        return (raw, rt);
    }

    public void SetRefreshCookie(HttpResponse response, string rawRefreshToken, bool isDev)
    {
        response.Cookies.Append("nsi_refresh", rawRefreshToken, new CookieOptions
        {
            HttpOnly = true,
            Secure = !isDev,           // ✅ dev: false, prod: true
            SameSite = SameSiteMode.Lax,
            Path = "/"
        });
    }

    private static string HashToken(string raw)
    {
        var bytes = Encoding.UTF8.GetBytes(raw);
        var hash = SHA256.HashData(bytes);
        return Convert.ToBase64String(hash);
    }

    public static string HashRefreshToken(string raw)
    {
        var bytes = Encoding.UTF8.GetBytes(raw);
        var hash = SHA256.HashData(bytes);
        return Convert.ToBase64String(hash);
    }
}