using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using NSI.Api.Infrastructure.Data;

namespace NSI.Api.Features.Acp;

[ApiController]
[Route("acp")]
[Authorize(Policy = "RequireAcpAccess")]
public sealed class AcpController : ControllerBase
{
    private readonly AppDbContext _db;

    public AcpController(AppDbContext db) => _db = db;

    [HttpGet("health")]
    public async Task<IActionResult> Health(CancellationToken ct)
    {
        // DB check (fast + real)
        var dbOk = await _db.Database.CanConnectAsync(ct);

        return Ok(new
        {
            ok = true,
            db = dbOk ? "ok" : "down",
            timeUtc = DateTimeOffset.UtcNow
        });
    }

    [HttpGet("metrics")]
    public async Task<IActionResult> Metrics(CancellationToken ct)
    {
        var startedAt = System.Diagnostics.Process.GetCurrentProcess().StartTime.ToUniversalTime();
        var uptimeSeconds = (DateTime.UtcNow - startedAt).TotalSeconds;

        // quick DB latency check
        var sw = System.Diagnostics.Stopwatch.StartNew();
        await _db.Database.ExecuteSqlRawAsync("SELECT 1", ct);
        sw.Stop();

        return Ok(new
        {
            ok = true,
            env = Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT") ?? "Unknown",
            uptimeSeconds = Math.Round(uptimeSeconds, 0),
            dbPingMs = sw.ElapsedMilliseconds
        });
    }
}