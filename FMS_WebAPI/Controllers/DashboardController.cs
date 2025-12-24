using Dapper;
using FMS_WebAPI.Model;
using FMS_WebAPI.Repository.IRepositoryService;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using System.Data;
using System.Data.Common;
using System.Data.SqlClient;
using System.IO.Compression;
using System.Net;
using System.Reflection;
using System.Security.Cryptography.Xml;
using System.Text;

namespace FMS_WebAPI.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    [Authorize]
    public class DashboardController : Controller
    {
        private readonly IAuthService _authService;
        private readonly IConfiguration _configuration;
        private readonly IDapperDbConnection _dbConnection;
        private readonly ICommonService _commonService;
        private readonly FileSettings _fileSettings;
        private readonly string keyString;

        public DashboardController(IAuthService authService, SqlConnection sqlConnection, IConfiguration configuration, IDapperDbConnection connection ,ICommonService commonService ,IOptions<FileSettings> filesetting)
        {
            _authService = authService;
            _configuration = configuration;
            _dbConnection = connection;
            _commonService = commonService;
            _fileSettings = filesetting.Value;
            keyString = _configuration["EncryptionKey"];

        }

         [HttpGet("GetUploads_NT")]
         public async Task<IActionResult> GetUploads()
            {
                var responseObject = new ResponseObject<object>();
                try
                {
                    int parameter1 = 0;
                    int parameter2 = 0;
                    int parameter3 = 0;
                    int parameter4 = 0;
                    string parameter5 = null;
                    string parameter6 = null;
                    string parameter7 = null;
                    string parameter8 = null;
                    using var connection = _dbConnection.CreateConnection();
                    // Setup Dapper parameters
                    var parameters = new DynamicParameters();
                    parameters.Add("@Parameter1", parameter1, DbType.Int32);
                    parameters.Add("@Parameter2", parameter2, DbType.Int32);
                    parameters.Add("@Parameter3", parameter3, DbType.Int32);
                    parameters.Add("@Parameter4", parameter4, DbType.Int32);
                    parameters.Add("@Parameter5", parameter5, DbType.String);
                    parameters.Add("@Parameter6", parameter6, DbType.String);
                    parameters.Add("@Parameter7", parameter7, DbType.String);
                    parameters.Add("@Parameter8", parameter8, DbType.String);
                    // Execute stored procedure and map to Invoice model
                    var invoices = await connection.QueryAsync<Invoice_Model>("SP_GET_INVOICE_DEATAILS",parameters,commandType: CommandType.StoredProcedure);
                    if (invoices.Any())
                    {
                        responseObject.Status = "Success";
                        responseObject.Message = "Invoice Details Fetch Successfully";
                        responseObject.Data = invoices;
                    }
                    else
                    {
                        responseObject.Status = "Success";
                        responseObject.Message = "No Data Available";
                        responseObject.Data = invoices;
                    }
                        return Ok(responseObject);
                }
                catch (Exception ex)
                {
                    responseObject.Status = "Error";
                    responseObject.Message = $"Error retrieving invoices: {ex.Message}";
                    responseObject.Data = null;
                    return Ok(responseObject);
                }
            }

        // Fetching Details of Uploaded Files against Invoice Mkey  
        [HttpGet("GetUploadFileRec-By_Mkey_NT")]
        public async Task<IActionResult> GetUploadFileRec(string mkey ,int? Session_userId ,int?Business_GroupId)
        {
            var responseObject = new ResponseObject<object>();
            try
            {
                using var connection = _dbConnection.CreateConnection();
                var parameters = new DynamicParameters();
                parameters.Add("@Parameter1", mkey, DbType.Decimal);
                parameters.Add("@Parameter2", 0, DbType.Decimal); // optional
                parameters.Add("@Session_userId", Session_userId, DbType.Int32); // optional
                parameters.Add("@Business_GroupId", Business_GroupId, DbType.Int32); // optional
                // Execute stored procedure and map results
                var documents = await connection.QueryAsync<InvoiceDocumentModel>("SP_GET_INVOICE_DOC_DEATAILS",parameters,commandType: CommandType.StoredProcedure);
                if (documents.Any())
                {
                    //var encryptResponse = _commonService.EncryptionObje<List<InvoiceDocumentModel>>(documents, keyString);
                    responseObject.Status = "Success";
                    responseObject.Message = "INVOICE_DOC_DEATAILS Fetch Successfully";
                    responseObject.Data = documents;
                    return Ok(responseObject);
                }
                else
                {
                    responseObject.Status = "Success";
                    responseObject.Message = "No Data Available";
                    responseObject.Data = documents.ToList();
                    return Ok(responseObject);
                }
            }
            catch(Exception ex)
            {
                responseObject.Status = "Error";
                responseObject.Message = $"Error retrieving invoices: {ex.Message}";
                responseObject.Data = null;
                return Ok(responseObject);
            }
        }

        // Fetching Uploaded File from Database based on Mkey and Sr No
        [HttpPost("ReadFileUploaded_NT")]
        public async Task<IActionResult> ReadFileUploaded([FromBody] ReadFileUpload_Model upload_Model)
        {
            var responseObject = new ResponseObject<object>();

            try
            {
                using var connection = _dbConnection.CreateConnection();
                await ((SqlConnection)connection).OpenAsync();

                string query = @"SELECT mkey AS MKEY,FileContents, FILE_NAME FROM INVOICE_DOC_TRL WHERE mkey = @Identifier AND SR_NO = @SrNo";
                using var command = new SqlCommand(query, (SqlConnection)connection);
                command.Parameters.AddWithValue("@Identifier", upload_Model.Identifier);
                command.Parameters.AddWithValue("@SrNo", upload_Model.SrNo);
                using var reader = await command.ExecuteReaderAsync();
                if (!await reader.ReadAsync())
                {
                    responseObject.Status = "Failed";
                    responseObject.Message = "No file found.";
                    return NotFound(responseObject);
                }

                // Read data
                byte[] fileBytes = (byte[])reader["FileContents"];
                string fileName = reader["FILE_NAME"].ToString();

                // Convert bytes to Base64 string
                string base64 = Convert.ToBase64String(fileBytes);

                // Bind into Model
                var fileModel = new FileUploadResultModel
                {
                    MKey = (int)reader["MKEY"],
                    FileName = fileName,
                    Base64File = base64,
                    ContentType = "application/pdf"
                };

                // Return as JSON
                responseObject.Status = "Success";
                responseObject.Message = "File retrieved successfully";
                responseObject.Data = fileModel;

                return Ok(responseObject);
            }
            catch (Exception ex)
            {
                responseObject.Status = "Error";
                responseObject.Message = $"Error: {ex.Message}";
                responseObject.Data = null;
                return StatusCode(500, responseObject);
            }
        }

        [HttpPost("Dashboard-insertUploadFile")]
        public async Task<IActionResult> InsertUploadFile([FromBody] FileUploadModel fileUpload)
        {
            var responseObject = new ResponseObject<object>();
            if (fileUpload.FileAttachment == null || fileUpload.FileAttachment.Length == 0) 
            { 
                return BadRequest(new { status = "error", message = "File not provided" }); 
            }
            byte[] fileBytes; 
            using (var ms = new MemoryStream()) 
            { 
                await fileUpload.FileAttachment.CopyToAsync(ms); fileBytes = ms.ToArray(); 
            }
            try
            {
                using var connection = _dbConnection.CreateConnection();
                await ((SqlConnection)connection).OpenAsync(); 
                string statement;
                var userName = User.Identity.Name;
                int UserId= await _authService.GetUserIdbyUserName(userName);
                // Convert Base64 string back to byte array
                //byte[] fileBytes = Convert.FromBase64String(fileUpload.Base64File);
                if (fileUpload.MODE == "M") 
                {
                    statement = @"UPDATE INVOICE_DOC_TRL SET FILECONTENTS = @FileContents, FILE_NAME = @FileName, UPLOADED_BY = @Action_by, UPLOAD_DATE = GETDATE(), STATUS_FLAG = @Action, LAST_UPDATED_BY = @Action_by, LAST_UPDATE_DATE = GETDATE() WHERE MKEY = @Mkey AND SR_NO = @Entry_Sr_no;"; 
                } 
                else 
                { 
                    statement = @"INSERT INTO INVOICE_DOC_TRL (FileContents, FileName, UPLOADED_BY, UPLOAD_DATE, STATUS_FLAG) VALUES (@FileContents, @FileName, @Action_by, GETDATE(), @Action); SELECT CAST(SCOPE_IDENTITY() AS int);"; 
                }

                var parameters = new DynamicParameters(); 
                parameters.Add("@FileContents", fileBytes, DbType.Binary); 
                parameters.Add("@FileName", fileUpload.FileName); 
                parameters.Add("@Mkey", fileUpload.Mkey); 
                parameters.Add("@Entry_Sr_no", fileUpload.Entry_Sr_no); 
                parameters.Add("@Action_by", string.IsNullOrEmpty(fileUpload.Action_by) ? UserId : fileUpload.Action_by); 
                parameters.Add("@Action", fileUpload.Action);

                int newId = 0; 
                if (fileUpload.MODE == "M") 
                { 
                    await connection.ExecuteAsync(statement, parameters); 
                } 
                else 
                {
                    newId = await connection.ExecuteScalarAsync<int>(statement, parameters); 
                }

                // Update header status
                string headerUpdate = @"UPDATE INVOICE_hdr SET status_flag = @Action WHERE mkey = @Mkey"; 
                await connection.ExecuteAsync(headerUpdate, new { Action = fileUpload.Action, Mkey = fileUpload.Mkey });
                responseObject.Status = "Success";
                responseObject.Message = "File uploaded successfully";
                responseObject.Data = new { Mkey = newId, FileName = fileUpload.FileName, };
                return Ok(responseObject);
                //return Ok(new { status = "success", message = "File uploaded successfully", Data =  new {Mkey= newId ,FileName= fileUpload.FileName , } });
            }
            catch (Exception ex)
            {
                responseObject.Status = "Error";
                responseObject.Message = $"Error uploading file: {ex.Message}";
                responseObject.Data = null;
                return StatusCode(500, responseObject);
            }
        }

        [HttpPost("Upload-File_NT")]
        public async Task<IActionResult> EncryptFiles([FromBody] CommonEncryptRsw commonEncrypt)   //CommonEncryptRsw commonEncrypt   //List<DocumentUploadModel> documentUpload
        {
            var responseObject = new ResponseObject<List<DocumentInsertResponse>>
            {
                Status = "Error",
                Message = "Error saving encrypted files",
                Data = new List<DocumentInsertResponse>()
            };

            if (string.IsNullOrEmpty(commonEncrypt.encryptjosn))
            {
                return BadRequest("Encrypted payload is missing");
            }

            //if (documentUpload == null || !documentUpload.Any())
            //    return BadRequest("No files uploaded");

           // string keyString = _configuration["EncryptionKey"];
            List<DocumentInsertResponse> documentUploadsList = new List<DocumentInsertResponse>();
            //var decryptedFiles = _commonService.DecryptFileDataWithNamesList("Upload_payload.txt",commonEncrypt.encryptjosn, keyString);
            //var PassworsHash = _authService.DecryptPassword(commonEncrypt.encryptjosn, keyString);
            //var documentUploadModels = System.Text.Json.JsonSerializer.Deserialize<List<DocumentUploadModel>>(PassworsHash);
           // var DocumentuploadModel = System.Text.Json.JsonSerializer.Deserialize<List<DocumentUploadModel>>(PassworsHash);
            //var changePaswordModel = _commonService.DecryptObject<DocumentUploadModel>(commonEncrypt.encryptjosn, keyString);
            var documentUpload = _commonService.DecryptObject<List<DocumentUploadModel>>(commonEncrypt.encryptjosn, keyString);
            //var documentUpload = _commonService.DecryptObjects<List<DocumentUploadModel>>(commonEncrypt.encryptjosn, keyString);
            try
            {
                if(documentUpload.Count() > 0)
                {
                    foreach (var file in documentUpload)
                    {
                        // Encrypt object
                        var encryptedFile = _commonService.EncryptionObje<DocumentUploadModel>(file, keyString);
                        var userwareHouses = _commonService.DecryptObject<DocumentUploadModel>(encryptedFile, keyString);
                        userwareHouses.FILECONTENTS = userwareHouses.FILECONTENTVAR;
                        // Make The encrypt for FileContents
                        var encryptedInvoiceModel = new Invoice_EncryptedModel
                        {
                            MKEY = userwareHouses.MKEY,
                            FILE_NAME = userwareHouses.FILE_NAME,
                            DOC_NAME = userwareHouses.DOC_NAME,
                            DOC_TYPE = userwareHouses.DOC_TYPE,
                            FILECONTENTVAR = userwareHouses.FILECONTENTVAR,
                            FILECONTENTS = userwareHouses.FILECONTENTS,
                            FileContentType = userwareHouses.ATTRIBUTE5,
                        };

                        var encrypted_Invoice_DOCTrl = _commonService.EncryptionObje<Invoice_EncryptedModel>(encryptedInvoiceModel, keyString);
                        var Decrypt_Invoice_DOCTrl = _commonService.DecryptObject<Invoice_EncryptedModel>(encrypted_Invoice_DOCTrl, keyString);
                        userwareHouses.FILECONTENTVAR = encrypted_Invoice_DOCTrl;
                        // Insert into database
                        var spResponse = await _commonService.InsertInvoice_DOC_TRl(userwareHouses);
                        var insertResponse = new DocumentInsertResponse();
                        try
                        {
                            // Example logMessage: "MKEY: 4, SR_NO: 2, Message: Insert successful. MKEY=4, SR_NO=2"
                            var parts = spResponse.Split(',');
                            if (parts.Length >= 3)
                            {
                                insertResponse.MKEY = long.Parse(parts[0].Replace("MKEY:", "").Trim());
                                insertResponse.SR_NO = long.Parse(parts[1].Replace("SR_NO:", "").Trim());
                                insertResponse.Message = parts[2].Trim().Replace("Message:", "").Trim();
                                insertResponse.Status = insertResponse.Message.Contains("Success") ? "Success" : "Error";
                            }
                            else
                            {
                                insertResponse.Status = "Error";
                                insertResponse.Message = spResponse;
                            }
                        }
                        catch
                        {
                            insertResponse.Status = "Error";
                            insertResponse.Message = spResponse;
                        }
                        documentUploadsList.Add(insertResponse);
                    }
                    // Final response
                    responseObject.Data = documentUploadsList;
                    responseObject.Status = documentUploadsList.All(x => x.Status == "Success") ? "Success" : "Error";
                    responseObject.Message = responseObject.Status == "Success" ? "Files encrypted and saved successfully" : "Some files failed to save";
                    return Ok(responseObject);
                }
                else
                {
/*                  responseObject.Data = documentUpload.FirstOrDefault()*/;
                    responseObject.Status = "Success";
                    responseObject.Message = "No Data Available ";
                    return Ok(responseObject);
                }
                
            }
            catch (Exception ex)
            {
                responseObject.Status = "Error";
                responseObject.Message = $"Error: {ex.Message}";
                return Ok(responseObject);
            }
        }

        

        [HttpPost("Download")]
        public async Task<IActionResult> DownloadFile([FromBody ] CommonEncryptRsw commonEncrypt)    //Downloadfile downloadfile  ,CommonEncryptRsw commonEncrypt
        {
            var responseObject = new ResponseObject<object>();
            try
            {
                string keyString = _configuration["EncryptionKey"];
                string _filePath = _configuration["FileSettings:FilePath"];

                if (string.IsNullOrEmpty(commonEncrypt.encryptjosn))
                {
                    return BadRequest("Encrypted payload is missing");
                }

                //var downloadfilepayload = _commonService.EncryptionObje<Downloadfile>(downloadfile, keyString);
                var decryptdownloadfile = _commonService.DecryptObject<Downloadfile>(commonEncrypt.encryptjosn, keyString);
                if (decryptdownloadfile == null)
                    return BadRequest("Invalid download Files parameters");

                //var doc = await _commonService.GetInvoiceDocAsync(downloadfile.mkey, downloadfile.srNo);
                var doc = await _commonService.GetInvoiceDocAsync(decryptdownloadfile.mkey, decryptdownloadfile.srNo);
                if (doc == null)
                    return NotFound("File not found");
                var Decrypt_Invoice_DOCTrl = _commonService.DecryptObject<Invoice_EncryptedModel>(doc.FILECONTENTVAR, keyString);
                byte[] fileBytes = Convert.FromBase64String(Decrypt_Invoice_DOCTrl.FILECONTENTVAR);
                string contentType = string.IsNullOrEmpty(doc.ATTRIBUTE5) ? "application/octet-stream" : doc.ATTRIBUTE5;
                string folderPath = Path.Combine(_filePath);
                if (!Directory.Exists(folderPath))
                    Directory.CreateDirectory(folderPath);

                // Full file path
                string filePath = Path.Combine(folderPath, doc.FILE_NAME);
                await System.IO.File.WriteAllBytesAsync(filePath, fileBytes);

                // Save path in DB
                //SavePathToDB(dto.FileName, filePath);
                Response.Headers.Add("Content-Disposition", $"attachment; filename=\"{doc.FILE_NAME}\"");
                return File(fileBytes, "application/octet-stream", doc.FILE_NAME);

            }
            catch (Exception ex)
            {
                responseObject.Status = "Error";
                responseObject.Message = $"Error: {ex.Message}";
                return Ok(responseObject);
                //return StatusCode(500, $"Internal server error: {ex.Message}");
            }                                                                                                                                                                                                                                                   
            
        }

        #region
        ////Previouse Old Code 

        //[HttpPost("EncryptFiles")]
        //public async Task<IActionResult> EncryptFiles([FromForm] List<IFormFile> files)
        //{
        //    var Documentfile = new DocumentUploadModel();
        //    List<DocumentUploadModel> documentUploadsList = new List<DocumentUploadModel>();
        //    try
        //    {
        //        if (files == null || files.Count == 0)
        //            return BadRequest("No files uploaded");

        //        string keyString = _configuration["EncryptionKey"];

        //        // 1️⃣ Encrypt all uploaded files with filenames
        //        var encryptedFiles = await _commonService.EncryptFileDataWithNamesAsync(files, keyString);

        //        // Optional: Save encrypted files to folder
        //        string folderPath = Path.Combine("D:\\Uploads\\EncryptedFiles");
        //        if (!Directory.Exists(folderPath))
        //            Directory.CreateDirectory(folderPath);

        //        foreach (var encryptedBase64 in encryptedFiles)
        //        {
        //            byte[] encryptedBytes = Convert.FromBase64String(encryptedBase64);
        //            string savePath = Path.Combine(folderPath, Guid.NewGuid() + ".enc"); // Use GUID to avoid overwrites
        //            await System.IO.File.WriteAllBytesAsync(savePath, encryptedBytes);
        //        }

        //        // Optional: Decrypt files to verify (can be removed in production)
        //        var decryptedFiles = _commonService.DecryptFileDataWithNamesList(encryptedFiles, keyString);

        //        foreach (var file in decryptedFiles)
        //        {
        //            Documentfile.FILE_NAME = file.FileName;
        //            Documentfile.FILECONTENTS = file.FileBytes;
        //            Documentfile.DOC_NAME = Path.GetFileNameWithoutExtension(file.FileName);
        //            Documentfile.DOC_TYPE = Path.GetFileNameWithoutExtension(file.FileName);
        //            documentUploadsList.Add(Documentfile);
        //        }



        //        // This Part Used For Download The File
        //        //using var zipStream = new MemoryStream();
        //        //using (var archive = new ZipArchive(zipStream,ZipArchiveMode.Create ,true)) 
        //        //{

        //        //    foreach (var file in decryptedFiles)
        //        //    {
        //        //        var zipEntry = archive.CreateEntry(file.FileName);
        //        //        using var entryStream = zipEntry.Open();
        //        //        await entryStream.WriteAsync(file.FileBytes, 0, file.FileBytes.Length);
        //        //    }
        //        //}

        //        //zipStream.Position = 0;

        //        //return File(
        //        //    zipStream.ToArray(),
        //        //    "application/zip",
        //        //    "DecryptedFiles.zip"
        //        //);


        //        // Encrypt Part For Files
        //        foreach (var file in decryptedFiles)
        //        {
        //            string decryptedPath = Path.Combine(folderPath, "Decrypted_" + file.FileName);
        //            await System.IO.File.WriteAllBytesAsync(decryptedPath, file.FileBytes);
        //        }
        //        // 2️⃣ Return encrypted files as Base64 strings in JSON
        //        return Ok(new
        //        {
        //            Message = "Files encrypted successfully",
        //            EncryptedFiles = encryptedFiles,
        //            DecryptedFileNames = decryptedFiles.Select(f => f.FileName).ToList() // Optional for verification
        //        });

        //    }
        //    catch (Exception ex)
        //    {
        //        throw;
        //    }

        //}


        //[HttpGet("DownloadEncryptedFile")]
        //public IActionResult DownloadEncryptedFile(string storedFileName, string originalFileName)
        //{

        //    string basePath = _configuration["FileSettings:FilePath"];
        //    string filePath = Path.Combine(basePath, storedFileName);

        //    if (!System.IO.File.Exists(filePath))
        //        return NotFound("File not found");

        //    byte[] encryptedBytes = System.IO.File.ReadAllBytes(filePath);
        //    string key = _configuration["EncryptionKey"];

        //    byte[] fileBytes = _commonService.DecryptSecure(encryptedBytes, key);

        //    return File(
        //        fileBytes,
        //        "application/octet-stream",
        //        originalFileName
        //    );
        //}
        #endregion

    }
}
