using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Hosting;
using System.Security.Claims;
using System.Text.Json;
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
        _tokens.SetAccessCookie(Response, access, isDev);

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
        _tokens.SetAccessCookie(Response, access, isDev);

        return Ok(new
        {
            accessToken = access,
            user = new { id = user.Id, email = user.Email, displayName = user.DisplayName }
        });
    }

    [HttpPost("logout")]
    public async Task<IActionResult> Logout(CancellationToken ct)
    {
        // best-effort: revoke refresh token currently in cookie
        if (Request.Cookies.TryGetValue("nsi_refresh", out var raw) && !string.IsNullOrWhiteSpace(raw))
        {
            var hash = TokenService.HashRefreshToken(raw);

            var rt = await _db.RefreshTokens.FirstOrDefaultAsync(x =>
                x.TokenHash == hash &&
                x.RevokedAt == null &&
                x.ExpiresAt > DateTimeOffset.UtcNow, ct);

            if (rt is not null)
            {
                rt.RevokedAt = DateTimeOffset.UtcNow;
                await _db.SaveChangesAsync(ct);
            }
        }

        var isDev = HttpContext.RequestServices.GetRequiredService<IHostEnvironment>().IsDevelopment();
        _tokens.ClearRefreshCookie(Response, isDev);
        _tokens.ClearAccessCookie(Response, isDev);

        return Ok(new { ok = true });
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
        _tokens.SetAccessCookie(Response, access, isDev);

        return Ok(new { accessToken = access });
    }

    [HttpGet("github/start")]
    public IActionResult GitHubStart()
    {
        var clientId = _db.Database.GetDbConnection() is not null
            ? HttpContext.RequestServices.GetRequiredService<IConfiguration>()["GitHub:ClientId"]
            : HttpContext.RequestServices.GetRequiredService<IConfiguration>()["GitHub:ClientId"];

        var cfg = HttpContext.RequestServices.GetRequiredService<IConfiguration>();
        var ghClientId = cfg["GitHub:ClientId"]!;
        var callback = cfg["GitHub:CallbackUrl"]!;

        // CSRF protection for OAuth: state in short-lived cookie
        var state = Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32));

        Response.Cookies.Append("nsi_gh_state", state, new CookieOptions
        {
            HttpOnly = true,
            Secure = !HttpContext.RequestServices.GetRequiredService<IHostEnvironment>().IsDevelopment(),
            SameSite = SameSiteMode.Lax,
            Path = "/auth/github"
        });

        var authorizeUrl =
            $"https://github.com/login/oauth/authorize" +
            $"?client_id={Uri.EscapeDataString(ghClientId)}" +
            $"&redirect_uri={Uri.EscapeDataString(callback)}" +
            $"&scope={Uri.EscapeDataString("read:user user:email")}" +
            $"&state={Uri.EscapeDataString(state)}";

        return Redirect(authorizeUrl);
    }

    [HttpGet("github/callback")]
    public async Task<IActionResult> GitHubCallback([FromQuery] string code, [FromQuery] string state, CancellationToken ct)
    {
        var cfg = HttpContext.RequestServices.GetRequiredService<IConfiguration>();
        var env = HttpContext.RequestServices.GetRequiredService<IHostEnvironment>();
        var http = HttpContext.RequestServices.GetRequiredService<IHttpClientFactory>().CreateClient();

        // Validate state
        if (!Request.Cookies.TryGetValue("nsi_gh_state", out var expectedState) ||
            string.IsNullOrWhiteSpace(expectedState) ||
            expectedState != state)
        {
            return Unauthorized(new { error = "Invalid OAuth state." });
        }

        // Exchange code for token
        var tokenReq = new HttpRequestMessage(HttpMethod.Post, "https://github.com/login/oauth/access_token");
        tokenReq.Headers.Accept.ParseAdd("application/json");
        tokenReq.Content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["client_id"] = cfg["GitHub:ClientId"]!,
            ["client_secret"] = cfg["GitHub:ClientSecret"]!,
            ["code"] = code,
            ["redirect_uri"] = cfg["GitHub:CallbackUrl"]!,
            ["state"] = state
        });

        var tokenRes = await http.SendAsync(tokenReq, ct);
        if (!tokenRes.IsSuccessStatusCode)
            return StatusCode((int)tokenRes.StatusCode, new { error = "GitHub token exchange failed." });

        var tokenJson = await tokenRes.Content.ReadAsStringAsync(ct);
        var token = JsonSerializer.Deserialize<GitHubTokenResponse>(tokenJson);
        if (token?.access_token is null)
            return BadRequest(new { error = "GitHub did not return an access token." });

        // Fetch user
        var userReq = new HttpRequestMessage(HttpMethod.Get, "https://api.github.com/user");
        userReq.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token.access_token);
        userReq.Headers.UserAgent.ParseAdd("NSIreland");
        userReq.Headers.Accept.ParseAdd("application/vnd.github+json");

        var userRes = await http.SendAsync(userReq, ct);
        if (!userRes.IsSuccessStatusCode)
            return StatusCode((int)userRes.StatusCode, new { error = "GitHub user fetch failed." });

        var userJson = await userRes.Content.ReadAsStringAsync(ct);
        var ghUser = JsonSerializer.Deserialize<GitHubUserResponse>(userJson);
        if (ghUser is null || ghUser.id == 0)
            return BadRequest(new { error = "Invalid GitHub user payload." });

        var providerUserId = ghUser.id.ToString();

        // Find existing AuthAccount
        var account = await _db.AuthAccounts
            .Include(a => a.User)
            .FirstOrDefaultAsync(a => a.Provider == "github" && a.ProviderUserId == providerUserId, ct);

        User user;

        if (account is not null)
        {
            user = account.User;
        }
        else
        {
            // Create local user (email may be null depending on GitHub privacy)
            user = new User
            {
                Email = (ghUser.email?.Trim().ToLowerInvariant()),
                DisplayName = string.IsNullOrWhiteSpace(ghUser.name) ? ghUser.login : ghUser.name,
                Username = ghUser.login,
                AvatarUrl = ghUser.avatar_url,
                LastLoginAt = DateTimeOffset.UtcNow
            };

            _db.Users.Add(user);
            await _db.SaveChangesAsync(ct);

            await _provisioning.AssignDefaultRoleAsync(user, ct);

            account = new AuthAccount
            {
                UserId = user.Id,
                Provider = "github",
                ProviderUserId = providerUserId,
                ProviderUsername = ghUser.login
            };

            _db.AuthAccounts.Add(account);
            await _db.SaveChangesAsync(ct);
        }

        user.LastLoginAt = DateTimeOffset.UtcNow;
        await _db.SaveChangesAsync(ct);

        // Issue tokens
        var access = await _tokens.CreateAccessToken(user, ct);
        var (rawRefresh, _) = await _tokens.CreateRefreshTokenAsync(
            user,
            Request.Headers.UserAgent.ToString(),
            HttpContext.Connection.RemoteIpAddress?.ToString(),
            ct
        );

        _tokens.SetRefreshCookie(Response, rawRefresh, env.IsDevelopment());
        _tokens.SetAccessCookie(Response, access, env.IsDevelopment());

        // Redirect back to web (cookie-session):
        // use fragment so it doesn't hit server logs/proxies
        var webOrigin = cfg["GitHub:WebOrigin"]?.TrimEnd('/') ?? "https://nsireland.ie";
        var redirect = $"{webOrigin}/jobs";

        return Redirect(redirect);
    }

    [Authorize(Policy = "RequireAcpAccess")]
    [HttpGet("acp-test")]
    public IActionResult AcpTest()
    {
        return Ok(new { message = "ACP access granted." });
    }
}