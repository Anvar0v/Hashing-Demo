using Hashing.Models;

var sodiumLib = new SodiumLibrary();

var hash = sodiumLib.HashPassword("my_password", out var salt);

Console.WriteLine($"Hashed Password = {hash}");
Console.WriteLine($"Generated salt = {Convert.ToHexString(salt)}");

var isSuccess = sodiumLib.VerifyPassword("my_password", hash, salt);

Console.WriteLine($"Final Result = {isSuccess}");