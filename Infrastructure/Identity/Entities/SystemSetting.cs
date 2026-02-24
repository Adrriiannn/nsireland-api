using System.ComponentModel.DataAnnotations;

namespace NSI.Api.Infrastructure.Identity.Entities;

public sealed class SystemSetting
{
    [MaxLength(100)]
    public string Key { get; set; } = null!;

    [MaxLength(2000)]
    public string Value { get; set; } = null!;
}