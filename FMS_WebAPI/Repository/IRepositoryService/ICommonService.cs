using FMS_WebAPI.Model;

namespace FMS_WebAPI.Repository.IRepositoryService
{
    public interface ICommonService
    {
        byte[] GetKey(string keyString, int requiredLength);
        string EncryptionObje<T>(T obj, string keyString);
        T DecryptObject<T>(string encryptedBase64, string keyString);
        // Decrypt Files Method from Encrypt To Decryption Way
        byte[] DecryptFileBytes(string encryptedFileBase64, string keyString);
        string SendEmail(string sp_to, string sp_cc, string sp_bcc, string sp_subject, string sp_body, string sp_mailtype, string sp_display_name, List<string> lp_attachment, MailDetailsNT mailDetailsNT);
    }
}
