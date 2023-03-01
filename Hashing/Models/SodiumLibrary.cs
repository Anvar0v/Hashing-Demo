using System.Data;
using System.Security.Cryptography;
using System.Text;

namespace Hashing.Models;
public class SodiumLibrary
{
    const int key_size = 64;
    const int iterations = 350000;
    HashAlgorithmName hashAlgorithm = HashAlgorithmName.SHA384;

    public string HashPassword(string password,out byte[] salt)
    {
        salt = RandomNumberGenerator.GetBytes(key_size);

        var hash = Rfc2898DeriveBytes.Pbkdf2(
            Encoding.UTF8.GetBytes(password),
            salt,
            iterations,
            hashAlgorithm,
            key_size
            );

        return Convert.ToHexString(hash);
    }
    public bool VerifyPassword(string password, string hash, byte[] salt)
    {
        var hashToCompare = Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, hashAlgorithm, key_size);
        return hashToCompare.SequenceEqual(Convert.FromHexString(hash));
    }
}
