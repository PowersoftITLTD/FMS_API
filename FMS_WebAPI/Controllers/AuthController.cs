using Dapper;
using FMS_WebAPI.Model;
using FMS_WebAPI.Repository.IRepositoryService;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Newtonsoft.Json;
using System.Data;
using System.Data.SqlClient;
using System.Net;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using static System.Runtime.InteropServices.JavaScript.JSType;

namespace FMS_WebAPI.Controllers
{
    [Route("api/[controller]")]
    public class AuthController : Controller
    {
        private readonly IAuthService _authService;
        private readonly IConfiguration _configuration;
        private readonly IDapperDbConnection _dapperConnection;
        private readonly ICommonService _commonService;
        //const string APIKEY = "PSOFT-API-KEY";
        //const string APIKEYVALUE = "5D5KVRahTIZ5brjKSXmsktmUAK";
        public AuthController(IAuthService authService, SqlConnection sqlConnection, IConfiguration configuration, IDapperDbConnection dapperConnection, ICommonService commonService)
        {
            _authService = authService;
            _configuration = configuration;
            _dapperConnection = dapperConnection;
            _commonService = commonService;
        }

        [HttpPost("ValidateLogin")]
        public async Task<IActionResult> Login([FromBody] User userModel)
        {
            var keyString = _configuration["EncryptionKey"];
            var APIKEYVALUE = _configuration["APIKEYVALUE"];
            var APIKEY = _configuration["APIKEY"];
            var responseObject = new ResponseObject();

            try
            {
                //var receivedKey = Request.Headers[APIKEYVALUE].FirstOrDefault(); 
                //if (string.IsNullOrEmpty(receivedKey) || receivedKey != APIKEY) 
                //{ 
                //    return Unauthorized(new { message = "Unauthorized or invalid API key" }); 
                //}
                var response = await _authService.ValidateLogin(userModel);
                var UserEncrypted = _authService.UserEncryptedReponsone(userModel, keyString);
                if (response.User.USER_NAME == null || response.Token == "Invalid login name or password")
                {
                    responseObject.Status = "Error";
                    responseObject.Message = "Invalid username or password.";
                    return Unauthorized(responseObject);
                }
                if (UserEncrypted == null)
                {
                    responseObject.Status = "Error";
                    responseObject.Message = "Invalid user details.";
                    return Ok(responseObject);
                }
                //var responseObject = new { status = "Ok", Message = "Token Generate Successfully", Token = token, UserEncryptedDetails = UserEncrypted };
                //return Ok(new { Token= token , UserEncryptedDetails = UserEncrypted  ,Status= "OK"});
                //return Ok(responseObject);
                responseObject.Status = "Ok";
                responseObject.Message = "Token generated successfully.";
                responseObject.Data = new { ToKen = response.Token, user = response.User, warehouses= response.Warehouses , UserEncryptedDetails = UserEncrypted };
                return Ok(responseObject);
            }
            catch (Exception ex)
            {
                responseObject.Status = "Error";
                responseObject.Message = "An error occurred during login/registration.";
                responseObject.Data = new { error = ex.Message };
                return StatusCode(StatusCodes.Status500InternalServerError, responseObject);
            }
        }

        [HttpPost("WMSBarCode-ValidateLoginWithWHCode")]
        public async Task<IActionResult> ValidateLoginWithWHCode([FromBody] UserWarehouseCode userwareHouse)
        {
            var keyString = _configuration["EncryptionKey"];
            var APIKEYVALUE = _configuration["APIKEYVALUE"];
            var APIKEY = _configuration["APIKEY"];
            var responseObject = new ResponseObject();
            try
            {
                var receivedKey = Request.Headers[APIKEYVALUE].FirstOrDefault();
                if (string.IsNullOrEmpty(receivedKey) || receivedKey != APIKEY)
                {
                    return Unauthorized(new { message = "Unauthorized or invalid API key" });
                }
                var response = await _authService.ValidateLogin_WHCode(userwareHouse);
                var userModel = new User
                {
                    username = userwareHouse.username,
                    password = userwareHouse.password,
                    warehouseid = 0
                };
                var UserEncrypted = _authService.UserEncryptedReponsone(userModel, keyString);
                if (response.User.USER_NAME == null || response.Token == "Invalid login name or password")
                {
                    responseObject.Status = "Error";
                    responseObject.Message = "Invalid username or password.";
                    return Unauthorized(responseObject);
                }
                if (UserEncrypted == null)
                {
                    responseObject.Status = "Error";
                    responseObject.Message = "Invalid user details.";
                    return Ok(responseObject);
                }
                responseObject.Status = "Ok";
                responseObject.Message = "Token generated successfully.";
                responseObject.Data = new { ToKen = response.Token, user = response.User, warehouses = response.Warehouses, UserEncryptedDetails = UserEncrypted };
                return Ok(responseObject);
            }
            catch (Exception ex)
            {
                responseObject.Status = "Error";
                responseObject.Message = "An error occurred during login/registration.";
                responseObject.Data = new { error = ex.Message };
                return StatusCode(StatusCodes.Status500InternalServerError, responseObject);
                //return StatusCode(500, new { message = "An error occurred", error = ex.Message });
            }
        }

        [HttpPost("WMSBarCode-Login/Registration")]
        public async Task<IActionResult> LoginRegistration(DeviceRegistration deviceRegistration)
        {
            var responseObject = new ResponseObject();
            try
            {
                if (deviceRegistration == null || string.IsNullOrEmpty(deviceRegistration.deviceid) || string.IsNullOrEmpty(deviceRegistration.warehousecode))
                {
                    responseObject.Status = "Error";
                    responseObject.Message = "Please enter a valid DeviceId and WareHouseCode.";
                    return Ok(responseObject);
                    //return Ok(new { message = "Please Entry Valide User & Password " });
                }

                var result = await _authService.WMSBarCode_Registration(deviceRegistration);
                if (result.Status.Contains("success"))
                {
                    // Return result as an Ok response
                    responseObject.Status = "Ok";
                    responseObject.Message = result.Message;
                    responseObject.Data= result;
                    //responseObject.Data = new { message = result };
                    return Ok(responseObject);
                }
                else
                {
                    // Return result as an Ok response
                    responseObject.Status = "Error";
                    responseObject.Message = result.Message;
                    responseObject.Data = result.Data;
                    return Ok(responseObject);
                }
            }
            catch (Exception ex)
            {

                responseObject.Status = "Error";
                responseObject.Message = "An error occurred during login/registration.";
                responseObject.Data = new { error = ex.Message };
                return StatusCode(StatusCodes.Status500InternalServerError, responseObject);
                // Log and return error response
                // return StatusCode(500, new { message = "An error occurred", error = ex.Message });

            }
        }

        [Authorize]
        [HttpGet("UserDecryptedPasswordVerifying")]
        public async Task<IActionResult> UserDecryptedPasswordVerifying(string Password)
        {
            var responseObject = new ResponseObject();
            var userModel = new UserModel();
            try
            {
                //var Passwordhash = Convert.ToByte(Password);
                var keyString = _configuration["EncryptionKey"];
                var PassworsHash = _authService.DecryptPassword(Password, keyString);
                if (PassworsHash != null)
                {
                    string[] strDatat = PassworsHash.Split(':');
                    if (strDatat.Length >= 0)
                    {
                        userModel = new UserModel
                        {
                            Username = strDatat[0],
                            Password = strDatat[1]
                        };
                    }
                }
                var result = await _authService.VerifyingResponse(userModel.Username, userModel.Password);
                if (!string.IsNullOrEmpty(result.User.EMAIL))
                {
                    responseObject.Status = "Ok";
                    responseObject.Message = "User successfully Decrypted logged in Credential";
                    responseObject.Data = userModel;
                    //return Ok(new { Message = userModel, Status = "Ok" });
                    return Ok(responseObject);
                }
                else
                {
                    responseObject.Status = "Error";
                    responseObject.Message = "User Decryption Failed";
                    responseObject.Data = userModel;
                    //return Ok(new { Message = userModel, Status = "Ok" });
                    return Ok(responseObject);
                }
            }
            catch (Exception ex)
            {

                responseObject.Status = "Error";
                responseObject.Message = "An error occurred during login/registration.";
                responseObject.Data = new { error = ex.Message };
                return StatusCode(StatusCodes.Status500InternalServerError, responseObject);
               // return StatusCode(500, responseObject);
                //throw;
                // return StatusCode(500, new { message = "An error occurred", error = ex.Message });
            }
        }

        [Authorize]
        [HttpPost("WMSBarCode-GetWarehouseDetails")]
        public async Task<IActionResult> GetWarehouseDetails(WarehouseDetails warehouse)
        {
            var keyString = _configuration["EncryptionKey"];
            var APIKEYVALUE = _configuration["APIKEYVALUE"];
            var APIKEY = _configuration["APIKEY"];
            var responseObject = new ResponseObject();
            try
            {
                var receivedKey = Request.Headers[APIKEYVALUE].FirstOrDefault();
                if (string.IsNullOrEmpty(receivedKey) || receivedKey != APIKEY)
                {
                    return Unauthorized(new { message = "Unauthorized or invalid API key" });
                }
                var resultresponse = await _authService.GetWarehouseDetails(warehouse);
                if (resultresponse.Status == "Success")
                {
                    return Ok(resultresponse);
                }
                else
                {
                    return Ok(resultresponse);
                }

            }
            catch (Exception ex)
            {
                responseObject.Status = "Error";
                responseObject.Message = "An error occurred during fetching warehouse details.";
                responseObject.Data = new { error = ex.Message };
                return StatusCode(StatusCodes.Status500InternalServerError, responseObject);
                //return Ok(responseObject);
            }
        }
        [Authorize]
        [HttpPost("WMSBarCode-GetLocationDetails")]
        public async Task<IActionResult> GetLocationDetails(WarehouseDetails warehouse)
        {
            var keyString = _configuration["EncryptionKey"];
            var APIKEYVALUE = _configuration["APIKEYVALUE"];
            var APIKEY = _configuration["APIKEY"];
            var responseObject = new ResponseObject();
            try
            {
                var receivedKey = Request.Headers[APIKEYVALUE].FirstOrDefault();
                if (string.IsNullOrEmpty(receivedKey) || receivedKey != APIKEY)
                {
                    return Unauthorized(new { message = "Unauthorized or invalid API key" });
                }
                var resultresponse = await _authService.GetLocationDetails(warehouse);
                if (resultresponse.Status == "Success")
                {
                    return Ok(resultresponse);
                }
                else
                {
                    return Ok(resultresponse);
                }
            }
            catch (Exception ex)
            {
                responseObject.Status = "Error";
                responseObject.Message = "An error occurred during fetching warehouse details.";
                responseObject.Data = new { error = ex.Message };
                return StatusCode(StatusCodes.Status500InternalServerError, responseObject);
                //return Ok(responseObject);
            }
        }

        #region
        // File Decryption method Here 
        [HttpPost("Encrypted-Upload-File_TEST")]
        public async Task<IActionResult> UploadEncryptedFile([FromBody] EncryptedFileDto dto)
        {
            try
            {
                var key = _configuration["EncryptionKey"];

                // Decrypt file bytes
                byte[] fileBytes =_commonService.DecryptFileBytes(dto.EncryptedData, key);

                // Create folder
                string folderPath = Path.Combine("D:\\Uploads\\EncryptedFiles");
                if (!Directory.Exists(folderPath))
                    Directory.CreateDirectory(folderPath);

                // Full file path
                string filePath = Path.Combine(folderPath, dto.FileName);

                // Save file
                await System.IO.File.WriteAllBytesAsync(filePath, fileBytes);

                // Save path in DB
                //SavePathToDB(dto.FileName, filePath);

                Response.Headers.Add("Content-Disposition", $"attachment; filename=\"{dto.FileName}\"");
                return File(fileBytes, "application/octet-stream", dto.FileName);

                return Ok(new { message = "File uploaded successfully", filePath });
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }
        // Encrypt The Object and list Of Object 
        [HttpGet("Encrypt-GetConvertEncryptionKey_TEST")]
        public async Task<IActionResult> GetConvertEncryptionKey()
        {
            try
            {
                var user = new ObjectUser_Model { Id = 1, Name = "Amit", Email = "amit@example.com" };
                string encryptionKey = _configuration["EncryptionKey"];

                string encryptedUser = _commonService.EncryptionObje(user, encryptionKey);

                var usersList = new List<ObjectUser_Model>
                {
                  new ObjectUser_Model{ Id=1, Name="Amit", Email="amit@example.com" },
                  new ObjectUser_Model{ Id=2, Name="Neha", Email="neha@example.com" }
               };

                string encryptedList = _commonService.EncryptionObje(usersList, encryptionKey);

                if (!string.IsNullOrEmpty(encryptedUser))
                {
                    var userModel= _commonService.DecryptObject<ObjectUser_Model>(encryptedUser, encryptionKey);
                    var userModelList = _commonService.DecryptObject<List<ObjectUser_Model>>(encryptedList, encryptionKey);
                    //var userModelList = DecryptObject<ObjectUser_Model>(encryptedList, encryptionKey);
                    return Ok(new { Status = "Success", EncryptedData = encryptedUser , Message= "Data Fetch Successfully" ,Decrypted= userModel , DecryptedList = userModelList });
                }
                else
                {
                    return Ok(new { Status = "Success", EncryptedData = encryptedUser, Message = "No Data Available" });
                }
               
            }
            catch(Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }

        [HttpPost("EncryptedLogin_User")]
        public async Task<IActionResult> EncryptedLogin_User([FromBody]EncryptedLogin_Model encryptedLogin)
        {
            var responseObject= new ResponseObject();
            var userModel = new UserModel();
            try
            {
                //var Passwordhash = Convert.ToByte(Password);
                var keyString = _configuration["EncryptionKey"];
                var PassworsHash = _authService.DecryptPassword(encryptedLogin.loginCredential, keyString);
                if (PassworsHash != null)
                {
                    string[] strDatat = PassworsHash.Split(':');
                    if (strDatat.Length >= 0)
                    {
                        userModel = new UserModel
                        {
                            Username = strDatat[0],
                            Password = strDatat[1]
                        };
                    }
                }
                var result = await _authService.VerifyingResponse(userModel.Username, userModel.Password);
                if (!string.IsNullOrEmpty(result.User.EMAIL) && (!string.IsNullOrEmpty(result.User.LOGIN_NAME)))
                {
                    responseObject.Status = "Ok";
                    responseObject.Message = "User successfully Decrypted logged in Credential";
                    responseObject.Data = result;
                    //return Ok(new { Message = userModel, Status = "Ok" });
                    return Ok(responseObject);
                }
                else
                {
                    responseObject.Status = "Error";
                    responseObject.Message = "User Decryption Failed";
                    responseObject.Data = result;
                    //return Ok(new { Message = userModel, Status = "Ok" });
                    return Ok(responseObject);
                }
            }
            catch (Exception ex)
            {

                responseObject.Status = "Error";
                responseObject.Message = "An error occurred during login/registration.";
                responseObject.Data = new { error = ex.Message };
                return StatusCode(StatusCodes.Status500InternalServerError, responseObject);
                // return StatusCode(500, responseObject);
                //throw;
                // return StatusCode(500, new { message = "An error occurred", error = ex.Message });
            }
        }


        #endregion
        #region
        //[HttpGet("DecryptedPassword")]
        //public IActionResult DecryptedPassword(string Password)
        //{
        //    try
        //    {
        //        var keyString = _configuration["EncryptionKey"];
        //        var PassworsHash = _authService.DecryptPassword(Password, keyString);
        //        return Ok(new { Message = PassworsHash });
        //    }
        //    catch (Exception ex)
        //    {
        //        //throw;
        //        return StatusCode(500, new { message = "An error occurred", error = ex.Message });

        //    }
        //}

        //[HttpPost("Encrypted-login")]
        //public async Task<IActionResult> Encrypted_Login([FromBody] EncryptedPayload body)
        //{
        //    if (body == null || string.IsNullOrEmpty(body.Payload))
        //        return BadRequest(new { message = "Missing payload" });

        //    try
        //    {
        //        // Step 1: Get key from config
        //        var keyString = _configuration["EncryptionKey"]; // full key
        //        //var keyString = "MAKV2SPBNIBVGFRTGFDERTYUBVDG8765"; // full key

        //        // Step 2: Decrypt payload
        //        string decrypted = DecryptPassword(body.Payload, keyString);
        //        // decrypted format: "username:password"

        //        // Step 3: Split username and password
        //        var parts = decrypted.Split(':');
        //        if (parts.Length != 2)
        //            return BadRequest(new { message = "Invalid decrypted payload format" });

        //        var username = parts[0];
        //        var password = parts[1];



        //        // Create Model To bind 

        //        var userModel = new UserModel
        //        {
        //            Username = username,
        //            Password = password
        //        };

        //        // Step 4: Validate user
        //        if (ValidateUser(username, password))
        //            return Ok(new { message = "Login successful" });
        //        else
        //            return Unauthorized(new { message = "Invalid credentials" });
        //    }
        //    catch (FormatException)
        //    {
        //        return BadRequest(new { message = "Payload is not valid Base64" });
        //    }
        //    catch (CryptographicException)
        //    {
        //        return BadRequest(new { message = "Decryption failed. Invalid key or IV." });
        //    }
        //    catch (Exception ex)
        //    {
        //        return BadRequest(new { message = "An error occurred", error = ex.Message });
        //    }
        //}

        //private static byte[] GetKey(string keyString, int requiredLength)
        //{
        //    if (keyString == null) keyString = string.Empty;
        //    byte[] key = Encoding.UTF8.GetBytes(keyString);

        //    if (key.Length == requiredLength)
        //        return key;

        //    var resized = new byte[requiredLength];
        //    Array.Copy(key, resized, Math.Min(key.Length, requiredLength));
        //    // If key is shorter: remaining bytes are zero (default)
        //    return resized;
        //}

        //public static byte[] DecryptFileBytes(string encryptedFileBase64, string keyString)
        //{
        //    if (string.IsNullOrEmpty(encryptedFileBase64))
        //        throw new ArgumentException("encryptedFileBase64 is null or empty", nameof(encryptedFileBase64));

        //    // Same key logic as your DecryptPassword
        //    byte[] key = GetKey(keyString, 32); // Ensure 32 bytes for AES-256

        //    using (Aes aesAlg = Aes.Create())
        //    {
        //        aesAlg.Key = key;
        //        aesAlg.Mode = CipherMode.CBC;
        //        aesAlg.Padding = PaddingMode.PKCS7;
        //        aesAlg.IV = new byte[16]; // Zero IV (must match encryption used in Angular)

        //        ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

        //        byte[] cipherBytes = Convert.FromBase64String(encryptedFileBase64);

        //        using (MemoryStream msDecrypt = new MemoryStream())
        //        {
        //            using (CryptoStream csDecrypt = new CryptoStream(new MemoryStream(cipherBytes), decryptor, CryptoStreamMode.Read))
        //            {
        //                csDecrypt.CopyTo(msDecrypt); // Copy decrypted bytes
        //            }
        //            return msDecrypt.ToArray(); // return file bytes
        //        }
        //    }
        //}

        //public static string EncryptionObje<T>(T obj, string keyString)
        //{
        //    string json = System.Text.Json.JsonSerializer.Serialize(obj);
        //    byte[] key = GetKey(keyString, 32);
        //    byte[] iv = new byte[16];

        //    using (Aes aes = Aes.Create())
        //    {
        //        aes.Key = key;
        //        aes.IV = iv;
        //        aes.Mode = CipherMode.CBC;
        //        aes.Padding = PaddingMode.PKCS7;

        //        ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
        //        byte[] plainBytes = Encoding.UTF8.GetBytes(json);
        //        byte[] cipherBytes = encryptor.TransformFinalBlock(plainBytes, 0, plainBytes.Length);
        //        return Convert.ToBase64String(cipherBytes);
        //    }
        //}

        //public static T DecryptObject<T>(string encryptedBase64, string keyString)
        //{
        //    byte[] key = GetKey(keyString, 32);
        //    byte[] iv = new byte[16];

        //    using (Aes aes = Aes.Create())
        //    {
        //        aes.Key = key;
        //        aes.IV = iv;
        //        aes.Mode = CipherMode.CBC;
        //        aes.Padding = PaddingMode.PKCS7;

        //        ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
        //        byte[] cipherBytes = Convert.FromBase64String(encryptedBase64);
        //        byte[] plainBytes = decryptor.TransformFinalBlock(cipherBytes, 0, cipherBytes.Length);

        //        string json = Encoding.UTF8.GetString(plainBytes);
        //        return System.Text.Json.JsonSerializer.Deserialize<T>(json);
        //    }
        //}

        //private void SavePathToDB(string fileName, string path)
        //{
        //    //using (var con = _dapperConnection.CreateConnection())
        //    //{
        //    //    con.Open();
        //    //    using (SqlCommand cmd = new SqlCommand("INSERT INTO FILE_UPLOADS (FileName, FilePath) VALUES (@file, @path)", con))
        //    //    {
        //    //        cmd.Parameters.AddWithValue("@file", fileName);
        //    //        cmd.Parameters.AddWithValue("@path", path);
        //    //        cmd.ExecuteNonQuery();
        //    //    }

        //    //}

        //    var param = new DynamicParameters();
        //    param.Add("@FileName", fileName);
        //    param.Add("@FilePath", path);

        //    using (var con = _dapperConnection.CreateConnection())
        //    {
        //        con.Execute("sp_InsertFilePath", param, commandType: CommandType.StoredProcedure);
        //    }

        //    //return Ok(new
        //    //{
        //    //    Message = "File decrypted, saved, and path stored successfully",
        //    //    Path = path,
        //    //    FileName = fileName,
        //    //    Status = "Success",
        //    //    SavedAt = DateTime.UtcNow
        //    //});
        //}

        //public string DecryptPassword(string encryptedPasswordBase64, string keyString)
        //{
        //    if (string.IsNullOrEmpty(encryptedPasswordBase64))
        //        throw new ArgumentException("encryptedPasswordBase64 is null or empty", nameof(encryptedPasswordBase64));

        //    byte[] key =_commonService.GetKey(keyString, 32); // Ensure 32 bytes for AES-256

        //    using (Aes aesAlg = Aes.Create())
        //    {
        //        aesAlg.Key = key;
        //        aesAlg.Mode = CipherMode.CBC;
        //        aesAlg.Padding = PaddingMode.PKCS7;
        //        aesAlg.IV = new byte[16]; // Zero IV (must match encryption)

        //        ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

        //        byte[] cipherBytes = Convert.FromBase64String(encryptedPasswordBase64);
        //        using (MemoryStream msDecrypt = new MemoryStream(cipherBytes))
        //        using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
        //        using (StreamReader srDecrypt = new StreamReader(csDecrypt, Encoding.UTF8))
        //        {
        //            return srDecrypt.ReadToEnd(); // returns "username:password"
        //        }
        //    }
        //}

        #endregion
        #region
        //[HttpPost("Plain-Encrypted")]
        //public async Task<IActionResult> EncryptedLogin([FromBody] RawJsonModel req)
        //{
        //    var raw = req.PlainText;
        //    //string rawJson = PlainText.ToString();
        //    var responseObject = new ResponseObject();
        //    var userModel = new UserModel();
        //    try
        //    {
        //        //var Passwordhash = Convert.ToByte(Password);
        //        var keyString = _configuration["EncryptionKey"];
        //        var PassworsHash = _authService.EncryptedReponsoneTest(raw, keyString);
        //        if (PassworsHash != null)
        //        {
        //            //string[] strDatat = PassworsHash.Split(':');
        //            //if (strDatat.Length >= 0)
        //            //{
        //            //    userModel = new UserModel
        //            //    {
        //            //        Username = strDatat[0],
        //            //        Password = strDatat[1]
        //            //    };
        //            //}
        //        }
        //        var result = await _authService.VerifyingResponse(userModel.Username, userModel.Password);
        //        if (!string.IsNullOrEmpty(result.User.EMAIL))
        //        {
        //            responseObject.Status = "Ok";
        //            responseObject.Message = "User successfully Decrypted logged in Credential";
        //            responseObject.Data = userModel;
        //            //return Ok(new { Message = userModel, Status = "Ok" });
        //            return Ok(responseObject);
        //        }
        //        else
        //        {
        //            responseObject.Status = "Error";
        //            responseObject.Message = "User Decryption Failed";
        //            responseObject.Data = userModel;
        //            //return Ok(new { Message = userModel, Status = "Ok" });
        //            return Ok(responseObject);
        //        }
        //    }
        //    catch (Exception ex)
        //    {

        //        responseObject.Status = "Error";
        //        responseObject.Message = "An error occurred during login/registration.";
        //        responseObject.Data = new { error = ex.Message };
        //        return StatusCode(500, responseObject);
        //        //throw;
        //        // return StatusCode(500, new { message = "An error occurred", error = ex.Message });
        //    }
        //}

        #endregion
    }
}
