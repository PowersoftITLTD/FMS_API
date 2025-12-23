using Dapper;
using FMS_WebAPI.Model;
using FMS_WebAPI.Repository.IRepositoryService;
using Microsoft.Extensions.Options;
using System.Data;
using System.Data.SqlClient;
using System.Net;
using System.Net.Mail;
using System.Security.Cryptography;
using System.Text;

namespace FMS_WebAPI.Repository.RepositoryService
{
    public class CommonService : ICommonService
    {
        private readonly IConfiguration _configuration;
        private readonly SqlConnection _connection;
        private readonly IDapperDbConnection _dbConnection;
        private readonly FileSettings _fileSettings;
        private readonly HostEnvironment _env;

        public CommonService(IConfiguration configuration, SqlConnection sqlConnection, IDapperDbConnection dbConnection, IOptions<FileSettings> fileSettings, IOptions<HostEnvironment> env)  //IUserService userService,
        {
            //_userService = userService;
            _configuration = configuration;
            _connection = sqlConnection;
            _dbConnection = dbConnection;
            _fileSettings = fileSettings.Value;
            _env = env.Value;

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


        public string SendEmail(string sp_to, string sp_cc, string sp_bcc, string sp_subject, string sp_body, string sp_mailtype, string sp_display_name, List<string> lp_attachment, MailDetailsNT mailDetailsNT)
        {
            string strerror = string.Empty;
            try
            {
                if (_env.env == "Production")
                {
                    using (MailMessage mail1 = new MailMessage())
                    {
                        mail1.From = new System.Net.Mail.MailAddress(mailDetailsNT.MAIL_FROM, sp_display_name.ToUpper());//, sp_display_name == "" ? dt.Rows[0]["MAIL_DISPLAY_NAME"].ToString() : sp_display_name
                                                                                                                         //mail1.To.Add("narendrakumar.soni@powersoft.in");
                        foreach (var to_address in sp_to.Replace(",", ";").Split(new[] { ";" }, StringSplitOptions.RemoveEmptyEntries))
                        {
                            mail1.To.Add(new MailAddress(to_address));
                            //mail1.To.Add(new MailAddress("narendrakumar.soni@powersoft.in"));
                            //mail.To.Add("ashish.tripathi@powersoft.in");
                            //mail.CC.Add("brijesh.tiwari@powersoft.in");
                        }
                        if (sp_cc != null)
                            foreach (var cc_address in sp_cc.Replace(",", ";").Split(new[] { ";" }, StringSplitOptions.RemoveEmptyEntries))
                            {
                                mail1.CC.Add(new MailAddress(cc_address));
                                // mail.CC.Add("brijesh.tiwari@powersoft.in");
                            }
                        if (sp_bcc != null)
                            foreach (var bcc_address in sp_bcc.Replace(",", ";").Split(new[] { ";" }, StringSplitOptions.RemoveEmptyEntries))
                            {
                                mail1.Bcc.Add(new MailAddress(bcc_address));
                            }

                        mail1.Subject = sp_subject;
                        mail1.Body = sp_body;
                        mail1.IsBodyHtml = true;
                        //mail1.Attachments.Add(new Attachment("C:\\file.zip"));

                        using (SmtpClient smtp1 = new SmtpClient(mailDetailsNT.SMTP_HOST.ToString(), Convert.ToInt32(mailDetailsNT.SMTP_PORT)))
                        {
                            smtp1.Credentials = new NetworkCredential(mailDetailsNT.MAIL_FROM, mailDetailsNT.SMTP_PASS.ToString());
                            //new NetworkCredential("autosupport@powersoft.in", "yivz qklg jsbv ttso");
                            smtp1.EnableSsl = mailDetailsNT.SMTP_ESSL.ToString() == "true" ? true : false;

                            if (lp_attachment != null)
                                foreach (var attach in lp_attachment)
                                {
                                    mail1.Attachments.Add(new Attachment(attach));
                                }

                            smtp1.Send(mail1);
                        }
                        foreach (Attachment attachment in mail1.Attachments)
                        {
                            attachment.Dispose();
                        }

                    }
                }
                strerror = "Sent Email";
                return strerror;


                /*MailMessage mail = new MailMessage();


                foreach (var to_address in sp_to.Replace(",", ";").Split(new[] { ";" }, StringSplitOptions.RemoveEmptyEntries))
                {
                    // mail.To.Add(new MailAddress(to_address));
                    mail.To.Add(new MailAddress("narendrakumar.soni@powersoft.in"));
                    //mail.To.Add("ashish.tripathi@powersoft.in");
                    //mail.CC.Add("brijesh.tiwari@powersoft.in");
                }
                if (sp_cc != null)
                    foreach (var cc_address in sp_cc.Replace(",", ";").Split(new[] { ";" }, StringSplitOptions.RemoveEmptyEntries))
                    {
                        mail.CC.Add(new MailAddress(cc_address));
                        // mail.CC.Add("brijesh.tiwari@powersoft.in");
                    }
                if (sp_bcc != null)
                    foreach (var bcc_address in sp_bcc.Replace(",", ";").Split(new[] { ";" }, StringSplitOptions.RemoveEmptyEntries))
                    {
                        mail.Bcc.Add(new MailAddress(bcc_address));
                    }

                mail.Subject = sp_subject;
                //mail.From = new System.Net.Mail.MailAddress(mailDetailsNT.MAIL_FROM, sp_display_name);//, sp_display_name == "" ? dt.Rows[0]["MAIL_DISPLAY_NAME"].ToString() : sp_display_name
                mail.From = new System.Net.Mail.MailAddress("autosupport@powersoft.in");//, sp_display_name == "" ? dt.Rows[0]["MAIL_DISPLAY_NAME"].ToString() : sp_display_name
                SmtpClient smtp = new SmtpClient();
                smtp.Timeout = Convert.ToInt32(mailDetailsNT.SMTP_TIMEOUT);
                smtp.Port = Convert.ToInt32(mailDetailsNT.SMTP_PORT);
                smtp.UseDefaultCredentials = true;
                smtp.Host = mailDetailsNT.SMTP_HOST.ToString();
//                sc.Credentials = basicAuthenticationInfo;
                smtp.Credentials = new NetworkCredential("autosupport@powersoft.in", "yivz qklg jsbv ttso");
                smtp.EnableSsl = mailDetailsNT.SMTP_ESSL.ToString() == "true" ? true : false;
                mail.IsBodyHtml = true;
                mail.Body = sp_body;
                if (lp_attachment != null)
                    foreach (var attach in lp_attachment)
                    {
                        mail.Attachments.Add(new Attachment(attach));
                    }
                smtp.Send(mail);*/


            }
            catch (Exception ex)
            {
                string FileName = string.Empty;
                string strFolder = string.Empty;

                strFolder = _fileSettings.FilePath; // "D:\\Application\\TaskDeployment" + "\\ErrorFolder";
                if (!Directory.Exists(strFolder))
                {
                    Directory.CreateDirectory(strFolder);
                }

                if (File.Exists(strFolder + "\\ErrorLog.txt") == false)
                {
                    using (System.IO.StreamWriter sw = File.CreateText(strFolder + "\\ErrorLog.txt"))
                    {
                        sw.Write("\n");
                        sw.WriteLine("--------------------------------------------------------------" + "\n");
                        sw.WriteLine(System.DateTime.Now);
                        sw.WriteLine(FileName + "--> " + ex.Message.ToString() + "\n");
                        sw.WriteLine("--------------------------------------------------------------" + "\n");
                    }
                }
                else
                {
                    using (System.IO.StreamWriter sw = File.AppendText(strFolder + "\\ErrorLog.txt"))
                    {
                        sw.Write("\n");
                        sw.WriteLine("--------------------------------------------------------------" + "\n");
                        sw.WriteLine(System.DateTime.Now);
                        sw.WriteLine(FileName + "--> " + ex.Message.ToString() + "\n");
                        sw.WriteLine("--------------------------------------------------------------" + "\n");
                    }
                }

                strerror = "Error Sending Email : " + ex.Message;
                return strerror;
            }
        }

        public async Task<string> InsertInvoice_DOC_TRl(DocumentUploadModel documentUpload)
        {
            try
            {
                using (IDbConnection db = _dbConnection.CreateConnection())
                {
                    db.Open(); // Ensure connection is open
                               using (var transaction = db.BeginTransaction()) 
                    { 
                        try 
                        {
                            //byte[] fileBytes = Base64ToVarbinarySafe(documentUpload.FILECONTENTS); 
                            byte[] fileBytes = Base64ToVarbinarySafe(documentUpload.FILECONTENTS);
                            var parameters = new DynamicParameters(); 
                            parameters.Add("@MKEY", documentUpload.MKEY); 
                            parameters.Add("@DOC_NAME", string.IsNullOrEmpty(documentUpload.DOC_NAME)?null :documentUpload.DOC_NAME); 
                            parameters.Add("@DOC_TYPE", string.IsNullOrEmpty(documentUpload.DOC_TYPE) ? null : documentUpload.DOC_TYPE); 
                            parameters.Add("@FILE_NAME", string.IsNullOrEmpty(documentUpload.FILE_NAME) ? null : documentUpload.FILE_NAME);
                            parameters.Add("@FILECONTENTS",(fileBytes == null || fileBytes.Length == 0)? (object)DBNull.Value: fileBytes,DbType.Binary);
                            //parameters.Add("@FILECONTENTS", fileBytes,DbType.Binary); // or DBNull.Value
                            parameters.Add("@FILECONTENTVAR", string.IsNullOrEmpty(documentUpload.FILECONTENTVAR) ? null : documentUpload.FILECONTENTVAR ,DbType.String ,size :-1);
                            parameters.Add("@UPLOADED_BY", documentUpload.UPLOADED_BY > 0 ? documentUpload.UPLOADED_BY :(object)DBNull.Value,DbType.Int64); 
                            parameters.Add("@IS_MANDATORY", string.IsNullOrEmpty(documentUpload.IS_MANDATORY) ? "Y" : documentUpload.IS_MANDATORY); 
                            parameters.Add("@STATUS_FLAG", string.IsNullOrEmpty(documentUpload.STATUS_FLAG) ? "P" : documentUpload.STATUS_FLAG); 
                            parameters.Add("@APPROVER_ID", documentUpload.APPROVER_ID > 0 ? documentUpload.APPROVER_ID : (object)DBNull.Value , DbType.Int64); 
                            parameters.Add("@ATTRIBUTE1", string.IsNullOrEmpty(documentUpload.ATTRIBUTE1) ? null : documentUpload.ATTRIBUTE1); 
                            parameters.Add("@ATTRIBUTE2", string.IsNullOrEmpty(documentUpload.ATTRIBUTE2) ? null : documentUpload.ATTRIBUTE2); 
                            parameters.Add("@ATTRIBUTE3", string.IsNullOrEmpty(documentUpload.ATTRIBUTE3) ? null : documentUpload.ATTRIBUTE3); 
                            parameters.Add("@ATTRIBUTE4", string.IsNullOrEmpty(documentUpload.ATTRIBUTE4) ? null : documentUpload.ATTRIBUTE4); 
                            parameters.Add("@ATTRIBUTE5", string.IsNullOrEmpty(documentUpload.ATTRIBUTE5) ? null : documentUpload.ATTRIBUTE5); 
                            parameters.Add("@CREATED_BY", documentUpload.CREATED_BY); 
                            parameters.Add("@LAST_UPDATED_BY", documentUpload.LAST_UPDATED_BY > 0 ? documentUpload.LAST_UPDATED_BY : (object)DBNull.Value, DbType.Int64); 
                            parameters.Add("@LAST_UPDATE_DATE", documentUpload.LAST_UPDATE_DATE.HasValue ? documentUpload.LAST_UPDATE_DATE.Value: (object)DBNull.Value ,DbType.DateTime); // Output parameters
                            parameters.Add("@NewSrNo", dbType: DbType.Int64, direction: ParameterDirection.Output); 
                            parameters.Add("@ResponseMessage", dbType: DbType.String, size: 200, direction: ParameterDirection.Output); 
                            // Execute stored procedure within transaction
                            await db.ExecuteAsync("InsertDocumentWithSrNo", parameters, commandType: CommandType.StoredProcedure, transaction: transaction); 
                            // Get output values
                            var srNo = parameters.Get<long?>("@NewSrNo"); 
                            var message = parameters.Get<string>("@ResponseMessage"); 
                            var logMessage = $"MKEY: {documentUpload.MKEY}, SR_NO: {srNo}, Message: {message}"; 
                            if (!srNo.HasValue) 
                            { 
                                // Rollback if insert failed
                                transaction.Rollback(); 
                                return logMessage;
                                // Return logMessage even on failure
                              } 
                            // Commit transaction if everything is fine
                            transaction.Commit(); 
                            return logMessage; // Return logMessage on success
                           } catch (Exception exTrans) 
                        { 
                            // Rollback on any exception
                            transaction.Rollback(); 
                            return $"Transaction failed and rolled back. Exception: {exTrans.Message}"; 
                        }
                    }
                }
            } catch (Exception ex) 
            {
                return $"Connection/Execution failed: {ex.Message}";
            }
        }

        public async Task<InvoiceDocDto> GetInvoiceDocAsync(decimal mkey, decimal srNo)
        {
            const string query = @"SELECT MKEY,SR_NO,DOC_NAME,DOC_TYPE,FILE_NAME,FILECONTENTS,FILECONTENTVAR, ATTRIBUTE5
                                 FROM INVOICE_DOC_TRL 
                                 WHERE MKEY = @MKEY
                                 AND SR_NO = @SR_NO";

            using (IDbConnection db = _dbConnection.CreateConnection())
            {
                if (db.State != ConnectionState.Open)
                    db.Open();

                var result = await db.QueryFirstOrDefaultAsync<InvoiceDocDto>(
                    query,
                    new
                    {
                        MKEY = mkey,
                        SR_NO = srNo
                    });

                return result;
            }
        }




        //public static byte[] Base64ToVarbinarySafe(string base64)
        //{
        //    if (string.IsNullOrWhiteSpace(base64))
        //        throw new ArgumentException("FILECONTENTVAR is empty");

        //    // Remove data URI prefix if present
        //    if (base64.Contains(","))
        //        base64 = base64.Substring(base64.IndexOf(",") + 1);

        //    // Remove whitespace
        //    base64 = base64
        //        .Replace("\r", "")
        //        .Replace("\n", "")
        //        .Replace(" ", "");

        //    // Fix padding
        //    base64 = base64.PadRight(
        //        base64.Length + (4 - base64.Length % 4) % 4, '=');

        //    // Validate Base64
        //    if (!Convert.TryFromBase64String(base64, new Span<byte>(new byte[base64.Length]), out _))
        //        throw new FormatException("FILECONTENTVAR is not valid Base64");

        //    return Convert.FromBase64String(base64);
        //}

        //public static byte[] Base64ToVarbinarySafe(string base64)
        //{
        //    if (string.IsNullOrWhiteSpace(base64))
        //        return Array.Empty<byte>();

        //    // Remove data URI prefix
        //    int commaIndex = base64.IndexOf(',');
        //    if (commaIndex >= 0)
        //        base64 = base64.Substring(commaIndex + 1);

        //    base64 = base64.Trim();

        //    try
        //    {
        //        return Convert.FromBase64String(base64);
        //    }
        //    catch (FormatException ex)
        //    {
        //        throw new FormatException("Invalid Base64 FILECONTENTVAR", ex);
        //    }
        //}

        public static byte[] Base64ToVarbinarySafe(string base64)
        {
            if (string.IsNullOrWhiteSpace(base64))
                return Array.Empty<byte>();

            // Remove data URI prefix (data:application/vnd.openxmlformats-officedocument.spreadsheetml.sheet;base64,)
            int commaIndex = base64.IndexOf(',');
            if (commaIndex >= 0)
                base64 = base64.Substring(commaIndex + 1);

            // Remove whitespace & line breaks
            base64 = base64
                .Replace("\r", "")
                .Replace("\n", "")
                .Replace("\t", "")
                .Replace(" ", "");

            // Fix padding if missing
            int padding = base64.Length % 4;
            if (padding > 0)
                base64 = base64.PadRight(base64.Length + (4 - padding), '=');

            // Handle URL-safe Base64
            base64 = base64
                .Replace('-', '+')
                .Replace('_', '/');

            try
            {
                return Convert.FromBase64String(base64);
            }
            catch (FormatException ex)
            {
                throw new FormatException(
                    $"Invalid Base64 content. Length={base64.Length}", ex);
            }
        }

    }
}
