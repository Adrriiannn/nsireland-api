using NSI.Api.App;
using NSI.Api.Infrastructure.Storage;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddBlobStorage(builder.Configuration);
builder.Services.AddOpenApi();

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.MapApp();

app.Run();