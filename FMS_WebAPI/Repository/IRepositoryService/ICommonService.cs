namespace FMS_WebAPI.Repository.IRepositoryService
{
    public interface ICommonService
    {
        byte[] GetKey(string keyString, int requiredLength);
        string EncryptionObje<T>(T obj, string keyString);
        T DecryptObject<T>(string encryptedBase64, string keyString);
        // Decrypt Files Method from Encrypt To Decryption Way
        byte[] DecryptFileBytes(string encryptedFileBase64, string keyString);
    }
}
