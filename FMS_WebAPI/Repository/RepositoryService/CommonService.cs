using FMS_WebAPI.Repository.IRepositoryService;
using System.Data.SqlClient;
using System.Security.Cryptography;
using System.Text;

namespace FMS_WebAPI.Repository.RepositoryService
{
    public class CommonService : ICommonService
    {
        private readonly IConfiguration _configuration;
        private readonly SqlConnection _connection;
        private readonly IDapperDbConnection _dbConnection;

        public CommonService(IConfiguration configuration, SqlConnection sqlConnection, IDapperDbConnection dbConnection)  //IUserService userService,
        {
            //_userService = userService;
            _configuration = configuration;
            _connection = sqlConnection;
            _dbConnection = dbConnection;
        }
        private byte[] GetKey(string keyString, int requiredLength)     // Static
        {
            if (keyString == null) keyString = string.Empty;
            byte[] key = Encoding.UTF8.GetBytes(keyString);

            if (key.Length == requiredLength)
                return key;

            var resized = new byte[requiredLength];
            Array.Copy(key, resized, Math.Min(key.Length, requiredLength));
            // If key is shorter: remaining bytes are zero (default)
            return resized;
        }

        public string EncryptionObje<T>(T obj, string keyString)
        {
            string json = System.Text.Json.JsonSerializer.Serialize(obj);
            byte[] key = GetKey(keyString, 32);
            byte[] iv = new byte[16];

            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
                byte[] plainBytes = Encoding.UTF8.GetBytes(json);
                byte[] cipherBytes = encryptor.TransformFinalBlock(plainBytes, 0, plainBytes.Length);
                return Convert.ToBase64String(cipherBytes);
            }
        }
        public T DecryptObject<T>(string encryptedBase64, string keyString)
        {
            byte[] key = GetKey(keyString, 32);
            byte[] iv = new byte[16];

            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
                byte[] cipherBytes = Convert.FromBase64String(encryptedBase64);
                byte[] plainBytes = decryptor.TransformFinalBlock(cipherBytes, 0, cipherBytes.Length);

                string json = Encoding.UTF8.GetString(plainBytes);
                return System.Text.Json.JsonSerializer.Deserialize<T>(json);
            }
        }

        // Files Decryption Method To Decrypt Files 
        public  byte[] DecryptFileBytes(string encryptedFileBase64, string keyString)   // Static
        {
            if (string.IsNullOrEmpty(encryptedFileBase64))
                throw new ArgumentException("encryptedFileBase64 is null or empty", nameof(encryptedFileBase64));

            // Same key logic as your DecryptPassword
            byte[] key = GetKey(keyString, 32); // Ensure 32 bytes for AES-256

            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = key;
                aesAlg.Mode = CipherMode.CBC;
                aesAlg.Padding = PaddingMode.PKCS7;
                aesAlg.IV = new byte[16]; // Zero IV (must match encryption used in Angular)

                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                byte[] cipherBytes = Convert.FromBase64String(encryptedFileBase64);

                using (MemoryStream msDecrypt = new MemoryStream())
                {
                    using (CryptoStream csDecrypt = new CryptoStream(new MemoryStream(cipherBytes), decryptor, CryptoStreamMode.Read))
                    {
                        csDecrypt.CopyTo(msDecrypt); // Copy decrypted bytes
                    }
                    return msDecrypt.ToArray(); // return file bytes
                }
            }
        }

        byte[] ICommonService.GetKey(string keyString, int requiredLength)
        {
            return GetKey(keyString, requiredLength);
        }
    }
}
