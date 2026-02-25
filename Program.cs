using NSI.Api.App;
using NSI.Api.Infrastructure.Storage;
using NSI.Api.Infrastructure.Data;
using NSI.Api.Infrastructure.Identity;
using NSI.Api.Infrastructure.Identity.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

var allowedOrigins = builder.Configuration
    .GetSection("Cors:AllowedOrigins")
    .Get<string[]>() ?? Array.Empty<string>();

builder.Services.AddBlobStorage(builder.Configuration);
builder.Services.AddOpenApi();
builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection"))
);
builder.Services.AddScoped<UserProvisioningService>();
builder.Services.AddScoped<PasswordHasher>();
builder.Services.AddScoped<TokenService>();
builder.Services.AddControllers();
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,

            ValidIssuer = builder.Configuration["Auth:JwtIssuer"],
            ValidAudience = builder.Configuration["Auth:JwtAudience"],
            IssuerSigningKey = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(builder.Configuration["Auth:JwtSigningKey"]!)
            ),

            ClockSkew = TimeSpan.FromSeconds(30)
        };


        options.Events = new JwtBearerEvents
        {
            OnMessageReceived = context =>
            {
                // Prefer Authorization header, but fall back to HttpOnly cookie.
                if (!string.IsNullOrWhiteSpace(context.Token))
                    return Task.CompletedTask;

                if (context.Request.Cookies.TryGetValue("nsi_access", out var cookieToken) &&
                    !string.IsNullOrWhiteSpace(cookieToken))
                {
                    context.Token = cookieToken;
                }

                return Task.CompletedTask;
            }
        };
    });

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("RequireAcpAccess",
        policy => policy.RequireClaim("perm", "acp.access"));

    options.AddPolicy("RequireWebEditorAccess",
        policy => policy.RequireClaim("perm", "editor.web.access"));

    options.AddPolicy("RequireCodeEditorAccess",
        policy => policy.RequireClaim("perm", "editor.code.access"));

    options.AddPolicy("RequireUsersRead",
        policy => policy.RequireClaim("perm", "users.read"));

    options.AddPolicy("RequireUsersWrite",
        policy => policy.RequireClaim("perm", "users.write"));
});

builder.Services.AddHttpClient();
builder.Services.AddCors(options =>
{
    options.AddPolicy("WebCors", policy =>
    {
        policy.WithOrigins(allowedOrigins)
              .AllowAnyHeader()
              .AllowAnyMethod()
              .AllowCredentials();
    });
});

var app = builder.Build();

app.UseRouting();
app.UseCors("WebCors");
app.UseAuthentication();
app.UseAuthorization();

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

// Identity seeding (roles/permissions/system settings)
// - In dev: enabled by default.
// - In prod: enable temporarily via Azure App Setting: Identity__SeedOnStartup=true
var seedIdentity = app.Environment.IsDevelopment() ||
                   app.Configuration.GetValue<bool>("Identity:SeedOnStartup");

if (seedIdentity)
{
    using var scope = app.Services.CreateScope();
    var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
    await db.Database.MigrateAsync();
    await IdentitySeed.SeedAsync(db);
}

app.MapGet("/build", () => Results.Ok(new { build = "seed-toggle-v1" }));

app.MapControllers();
app.MapApp();

app.Run();
