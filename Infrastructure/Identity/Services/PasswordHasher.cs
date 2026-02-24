using Konscious.Security.Cryptography;
using System.Security.Cryptography;
using System.Text;

namespace NSI.Api.Infrastructure.Identity.Services;

public sealed class PasswordHasher
{
    public async Task<string> HashAsync(string password, CancellationToken ct = default)
    {
        // Generate salt
        var salt = RandomNumberGenerator.GetBytes(16);

        // Argon2id parameters (good baseline)
        var argon2 = new Argon2id(Encoding.UTF8.GetBytes(password))
        {
            Salt = salt,
            DegreeOfParallelism = 2,
            Iterations = 3,
            MemorySize = 65536 // 64MB
        };

        var hash = await argon2.GetBytesAsync(32);

        // Store as: base64(salt).base64(hash)
        return $"{Convert.ToBase64String(salt)}.{Convert.ToBase64String(hash)}";
    }

    public async Task<bool> VerifyAsync(string password, string stored, CancellationToken ct = default)
    {
        var parts = stored.Split('.', 2);
        if (parts.Length != 2) return false;

        var salt = Convert.FromBase64String(parts[0]);
        var expected = Convert.FromBase64String(parts[1]);

        var argon2 = new Argon2id(Encoding.UTF8.GetBytes(password))
        {
            Salt = salt,
            DegreeOfParallelism = 2,
            Iterations = 3,
            MemorySize = 65536
        };

        var actual = await argon2.GetBytesAsync(32);
        return CryptographicOperations.FixedTimeEquals(actual, expected);
    }
}