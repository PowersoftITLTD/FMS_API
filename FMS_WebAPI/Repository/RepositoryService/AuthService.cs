using Dapper;
using FMS_WebAPI.Model;
using FMS_WebAPI.Repository.IRepositoryService;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.Data;
using System.Data.SqlClient;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks.Sources;

namespace FMS_WebAPI.Repository.RepositoryService
{
    public class AuthService  : IAuthService
    {
        //private readonly IUserService _userService;
        private readonly IConfiguration _configuration;
        private readonly SqlConnection _connection;
        private readonly IDapperDbConnection _dbConnection;
        private readonly ICommonService _commonService;

        public AuthService(IConfiguration configuration, SqlConnection sqlConnection, IDapperDbConnection dbConnection ,ICommonService commonService)  //IUserService userService,
        {
            //_userService = userService;
            _configuration = configuration;
            _connection = sqlConnection;
            _dbConnection = dbConnection;
            _commonService = commonService;
        }
       
        public async Task<LoginResponse> ValidateLogin(User _user)  // string apiKey
        {
            var response = new LoginResponse();
            using (var connection = _dbConnection.CreateConnection())
            {
                connection.Open();
                using (var multi = connection.QueryMultiple("Sp_Validate_Login",new{LoginName = _user.username,Password = _user.password,WarehouseID = _user.warehouseid},commandType: CommandType.StoredProcedure))
                {
                    //First result: UserDetails
                   var userDetails = multi.Read<UserDetailsModel>().FirstOrDefault();
                    if (userDetails == null)
                    {
                        // Check for error message in first table
                        var error = multi.Read<string>().FirstOrDefault();
                        response.Error = error ?? "Invalid login or password";
                        return response;
                    }
                    response.User = userDetails;
                    // Second result: Warehouses
                    var warehouses = multi.Read<WarehouseModel>().ToList();
                    response.Warehouses = warehouses;

                    // Generate JWT token
                    response.Token = GenerateToken(userDetails.USER_NAME, userDetails.MKEY);
                }
            }

            return response;
        }

        public async Task<LoginResponse> ValidateLogin_WHCode(UserWarehouseCode _userWarehouse)  // string apiKey
        {
            var response = new LoginResponse();
            using (var connection = _dbConnection.CreateConnection())
            {
                connection.Open();
                using (var multi = connection.QueryMultiple("Sp_Validate_Login_WHCode", new { LoginName = _userWarehouse.username, Password = _userWarehouse.password, WarehouseID = _userWarehouse.warehousecode }, commandType: CommandType.StoredProcedure))
                {
                    //First result: UserDetails
                    var userDetails = multi.Read<UserDetailsModel>().FirstOrDefault();
                    if (userDetails == null)
                    {
                        // Check for error message in first table
                        var error = multi.Read<string>().FirstOrDefault();
                        response.Error = error ?? "Invalid login or password";
                        return response;
                    }
                    response.User = userDetails;
                    // Second result: Warehouses
                    var warehouses = multi.Read<WarehouseModel>().ToList();
                    response.Warehouses = warehouses;

                    // Generate JWT token
                    response.Token = GenerateToken(userDetails.USER_NAME, userDetails.MKEY);
                }
            }

            return response;
        }

        public async Task<ResponseObject<dynamic>> WMSBarCode_Registration(DeviceRegistration _devicereg)
        {
            var responseObject = new ResponseObject<dynamic>();

            try
            {
                if (!string.IsNullOrEmpty(_devicereg.deviceid) &&
                    !string.IsNullOrEmpty(_devicereg.warehousecode))
                {
                    using (var connection = _dbConnection.CreateConnection())
                    {
                        connection.Open();

                        var parameters = new DynamicParameters();
                        parameters.Add("@userid", _devicereg.deviceid);
                        parameters.Add("@warehouseid", _devicereg.warehousecode);
                        parameters.Add("@LoginName", null);
                        parameters.Add("@Password", null);

                        var result = await connection.QueryFirstOrDefaultAsync<dynamic>(
                            "DeviceRegistration",
                            parameters,
                            commandType: CommandType.StoredProcedure);

                        if (result == null)
                        {
                            responseObject.Status = "Success";
                            responseObject.Message = "No data returned from SP";
                            responseObject.Data = null;
                            return responseObject;
                        }

                        responseObject.Status = "Success";
                        responseObject.Message = "Data Saved Successfully!";
                        responseObject.Data = result;
                        return responseObject;
                    }
                }

                responseObject.Status = "Error";
                responseObject.Message = "Invalid input parameters";
                responseObject.Data = null;
                return responseObject;
            }
            catch (Exception ex)
            {
                responseObject.Status = "Error";
                responseObject.Message = $"Error storing device registration: {ex.Message}";
                responseObject.Data = null;
                return responseObject;
            }
        }

        public async Task<ResponseObject<List<WarehouseDetails_Model>>> GetWarehouseDetails(WarehouseDetails warehouseModel)
        {
            var responseObject = new ResponseObject<List<WarehouseDetails_Model>>();
            var keyString = _configuration["EncryptionKey"];
            try
            {
                using (var connection = _dbConnection.CreateConnection())
                {
                    connection.Open();
                    var parameters = new DynamicParameters();
                    parameters.Add("@userid", warehouseModel.userid);
                    parameters.Add("@warehouseid", warehouseModel.warehouseid);
                    var warehouseDetails = await connection.QueryAsync<WarehouseDetails_Model>("Sp_getWarehouseDetails", parameters, commandType: CommandType.StoredProcedure); // Adjust the query as needed
                    if (warehouseDetails.Any())
                    {
                        //var encrypted = _commonService.EncryptionObje(warehouseDetails, keyString);
                        responseObject.Status = "Success";
                        responseObject.Message = "WareHouse Details Fetch Successfully";
                        responseObject.Data =  warehouseDetails.ToList();
                        return (responseObject);
                    }
                    else
                    {
                        responseObject.Status = "Success";
                        responseObject.Message = "No Data Available";
                        responseObject.Data = warehouseDetails.ToList();
                        return (responseObject);
                    }
                }

            }
            catch (Exception ex)
            {
                responseObject.Status = "Error";
                responseObject.Message = $"Error retrieving invoices: {ex.Message}";
                responseObject.Data = null;
                return (responseObject);
            }
        }

       public async Task<ResponseObject<List<LocationDetails_Model>>> GetLocationDetails(WarehouseDetails warehouseDetails)
        {
            var responseObject = new ResponseObject<List<LocationDetails_Model>>();
            try
            {
                using (var connection = _dbConnection.CreateConnection())
                {
                    connection.Open();
                    var parameters = new DynamicParameters();
                    parameters.Add("@userid", warehouseDetails.userid);
                    parameters.Add("@warehouseid", warehouseDetails.warehouseid);
                    var locationDetails = await connection.QueryAsync<LocationDetails_Model>("Sp_getLocationDetails", parameters, commandType: CommandType.StoredProcedure); // Adjust the query as needed
                    if (locationDetails.Any())
                    {
                        responseObject.Status = "Success";
                        responseObject.Message = "LOCATION_DEATAILS Fetch Successfully";
                        responseObject.Data = locationDetails.ToList();
                        return (responseObject);
                    }
                    else
                    {
                        responseObject.Status = "Success";
                        responseObject.Message = "No Data Available";
                        responseObject.Data = locationDetails.ToList();
                        return (responseObject);
                    }
                }
            }
            catch (Exception ex)
            {
                responseObject.Status = "Error";
                responseObject.Message = $"Error retrieving location details: {ex.Message}";
                responseObject.Data = null;
                return (responseObject);
            }
        }

       public string GenerateToken(string username, int userId)
        {
            var claims = new[]
                      {
                new Claim(ClaimTypes.Name, username),  // The user's login name
                new Claim("UserId", userId.ToString()), // Custom claim for UserId
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()) // Unique identifier for the JWT
                     };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:SecretKey"])); // Secret key from configuration
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256); // Signing credentials

            var token = new JwtSecurityToken(
                issuer: _configuration["Jwt:Issuer"],  // Issuer of the token
                audience: _configuration["Jwt:Audience"], // Audience for the token
                claims: claims, // Claims associated with the token
                expires: DateTime.Now.AddHours(1), // Token expiration time
                signingCredentials: creds // Signing credentials
            );

            // Return the JWT token
            return new JwtSecurityTokenHandler().WriteToken(token);
        }

       public byte[] UserEncryptedReponsone(User userModel, string keyString)
        {
            try
            {
                string combined = userModel.username + ":" + userModel.password; // Combine username and password with a separator (e.g., colon)

                byte[] key = GetKey(keyString, 32); // AES-256 requires a 32-byte key

                using (Aes aesAlg = Aes.Create())
                {
                    aesAlg.Key = key;
                    aesAlg.IV = new byte[16]; // Zeroed IV (not recommended for production)

                    ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                    using (MemoryStream msEncrypt = new MemoryStream())
                    {
                        using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                        {
                            using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                            {
                                swEncrypt.Write(combined); // Write combined username and password to be encrypted
                            }
                        }
                        return msEncrypt.ToArray(); // Return the encrypted data as byte array
                    }
                }

            }
            catch (Exception ex)
            {
                throw;
            }
        }

       // Decrypted Password 
       public string DecryptPassword(string encryptedPassword, string keyString)
        {
            byte[] key = GetKey(keyString, 32); // Ensure the key is 32 bytes (AES-256)

            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = key; // Set the AES key
                aesAlg.IV = new byte[16]; // Initialization Vector, set to 0 for simplicity (NOT recommended for production)

                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                using (MemoryStream msDecrypt = new MemoryStream(Convert.FromBase64String(encryptedPassword)))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {
                            return srDecrypt.ReadToEnd(); // Return the decrypted string
                        }
                    }
                }
            }
        }

       private static byte[] GetKey(string keyString, int requiredLength)
        {
            // Truncate or pad the key to the required length (AES-128 = 16 bytes, AES-192 = 24 bytes, AES-256 = 32 bytes)
            byte[] key = Encoding.UTF8.GetBytes(keyString);

            if (key.Length < requiredLength)
            {
                Array.Resize(ref key, requiredLength); // Pad with zeros if it's too short
            }
            else if (key.Length > requiredLength)
            {
                Array.Resize(ref key, requiredLength); // Truncate if it's too long
            }

            return key;
        }

       public async Task<int> GetUserIdbyUserName(string userName)
        {
            var cmd = new SqlCommand("SELECT MKEY As 'UserID' FROM [WMS_User_Mst] WHERE [LOGIN_NAME] = @UserName", _connection);
            cmd.Parameters.AddWithValue("@UserName", userName);
            if (_connection.State != ConnectionState.Open)
                await _connection.OpenAsync();
            var userId = (int?)await cmd.ExecuteScalarAsync();
            if (userId == null) throw new Exception("User not found");

            return userId.Value;
        }
       public async Task<LoginResponse> VerifyingResponse(string userLogin, string Password)
        {
            try
            {
                var response = new LoginResponse();
                using (var connection = _dbConnection.CreateConnection())
                {
                    connection.Open();
                    using (var multi = connection.QueryMultiple(
                        "Sp_Validate_Login",
                        new
                        {
                            LoginName = userLogin,
                            Password = Password,
                            WarehouseID =0 //_user.warehouseid
                        },
                        commandType: CommandType.StoredProcedure))
                    {
                        //First result: UserDetails
                        var userDetails = multi.Read<UserDetailsModel>().FirstOrDefault();
                        if (userDetails == null)
                        {
                            // Check for error message in first table
                            var error = multi.Read<string>().FirstOrDefault();
                            response.Error = error ?? "Invalid login or password";
                            return response;
                        }

                        response.User = userDetails;

                        // Second result: Warehouses
                        var warehouses = multi.Read<WarehouseModel>().ToList();
                        response.Warehouses = warehouses;

                        // Generate JWT token
                        response.Token = GenerateToken(userDetails.USER_NAME, userDetails.MKEY);
                    }
                }

                return response;

            }
            catch (Exception ex)
            {
                throw;
            }
        }

       public async Task<string> LoginRegistration(UserLoginModel userLogin)
        {
            try
            {
                if (userLogin == null)
                {
                    return "UserLogin is Empty";
                }
                var keyString = _configuration["EncryptionKey"]; // Retrieve the key from the configuration
                                                                 //var EncryptedHashPassword = EncryptPassword(userLogin.PasswordHash, keyString);
                var parameters = new DynamicParameters();
                parameters.Add("@pLogin", userLogin.LoginName);
                parameters.Add("@pPassword", userLogin.PasswordHash); // Assuming this is already hashed or encrypted as needed
                parameters.Add("@pFirstName", userLogin.FirstName);
                parameters.Add("@pLastName", userLogin.LastName);
                parameters.Add("@responseMessage", dbType: DbType.String, direction: ParameterDirection.Output, size: 500);
                await _connection.ExecuteAsync("dbo.uspAddUser", parameters, commandType: CommandType.StoredProcedure);
                string responseMessage = parameters.Get<string>("@responseMessage");
                if (!string.IsNullOrEmpty(responseMessage))
                {
                    return "User inserted successfully!";
                }
                else
                {
                    return "User registration failed.";
                }
            }
            catch (Exception ex)
            {
                return $"An error occurred: {ex.Message}";
            }
        }

        public async Task<ResponseObject<string>> ChangePassword(ChangePassword_Model changePassword)
        {
            var responseObject = new ResponseObject<string>();

            try
            {
                using (var connection = _dbConnection.CreateConnection())
                {
                    var parameters = new DynamicParameters();
                    parameters.Add("@UserId", changePassword.UserId);
                    parameters.Add("@OldPassword", changePassword.Previouse_Password);
                    parameters.Add("@NewPassword", changePassword.NewPassword);

                    // Add output parameter
                    parameters.Add("@responseMessage", dbType: DbType.String, size: 500, direction: ParameterDirection.Output);

                     await connection.ExecuteAsync(
                        "Sp_ChangePassword",
                        parameters,
                        commandType: CommandType.StoredProcedure
                    );
                    var responseObj= parameters.Get<string>("@responseMessage");
                    if(responseObj.Contains("Updated Successfully"))
                    {
                        responseObject.Status = "Success";
                        responseObject.Message = responseObj;
                        responseObject.Data = responseObj;
                    }
                    else
                    {
                        responseObject.Status = "Error";
                        responseObject.Message = responseObj;
                        responseObject.Data = responseObj;
                    }
                    //responseObject.Status = "Success"; // you can still decide to add "Error" based on message content
                    //responseObject.Message = parameters.Get<string>("@responseMessage");
                }
            }
            catch (Exception ex)
            {
                responseObject.Status = "Error";
                responseObject.Message = ex.Message;
            }

            return responseObject;
        }


        public async Task<ResponseObject<List<User_MST_Model>>> GetuserDetails_ByEmailId(string email)
        {
            var responseObject = new ResponseObject<List<User_MST_Model>>();
            try
            {
                using (var connection = _dbConnection.CreateConnection())
                {
                    connection.Open();
                    var parameters = new DynamicParameters();
                    parameters.Add("@Email", email);
                    //parameters.Add("@warehouseid", warehouseModel.warehouseid);
                    var warehouseDetails = await connection.QueryAsync<User_MST_Model>("Sp_GetUserDetailsByEmail", parameters, commandType: CommandType.StoredProcedure); // Adjust the query as needed

                    if (warehouseDetails.Any())
                    {
                        responseObject.Status = "Success";
                        responseObject.Message = "WareHouse Details Fetch Successfully";
                        responseObject.Data = warehouseDetails.ToList();
                        return (responseObject);
                    }
                    else
                    {
                        responseObject.Status = "Success";
                        responseObject.Message = "No Data Available";
                        responseObject.Data = warehouseDetails.ToList();
                        return (responseObject);
                    }
                }

            }
            catch (Exception ex)
            {
                responseObject.Status = "Error";
                responseObject.Message = $"Error retrieving invoices: {ex.Message}";
                responseObject.Data = null;
                return (responseObject);
            }
        }

        public async Task<IEnumerable<ResetPasswordOutPut_List>> GetResetPasswordAsync(string TEMPPASSWORD, string LoginName)
        {
            try
            {
                string strMessage = string.Empty;
                string Email= string.Empty;
                int ErrorNumber = 0;
                const string validChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:,.<>?";
                StringBuilder password = new StringBuilder();
                Random random = new Random();

                for (int i = 0; i < 10; i++)
                {
                    password.Append(validChars[random.Next(validChars.Length)]);
                }
                TEMPPASSWORD = password.ToString();

                using (IDbConnection db = _dbConnection.CreateConnection())
                {
                    var parmeters = new DynamicParameters();
                    parmeters.Add("@TEMPPASSWORD", TEMPPASSWORD);
                    parmeters.Add("@LoginName", LoginName);
                    var ResetPass = await db.QueryAsync<ResetPasswordOutPut>("sp_reset_password", parmeters, commandType: CommandType.StoredProcedure);

                    foreach (var ResetResponse in ResetPass)
                    {
                        ErrorNumber = ResetResponse.ErrorNumber;
                        strMessage = ResetResponse.Message;
                        Email= ResetResponse.EMAIL_ID_OFFICIAL;
                    }

                    if (ErrorNumber == 0)
                    {
                        //var AssiLoginName = await db.QueryAsync<string>(" Select UPPER(LEFT(FIRST_NAME,1))+LOWER(SUBSTRING(FIRST_NAME,2,LEN(FIRST_NAME))) + ' '+ " +
                        //           " UPPER(LEFT(LAST_NAME,1))+LOWER(SUBSTRING(LAST_NAME,2,LEN(LAST_NAME))) as EMP_FULL_NAME " +
                        //           " from EMPLOYEE_MST EMP_MST where " +
                        //           " (EMP_MST.EMAIL_ID_OFFICIAL = '" + LoginName + "' " +
                        //           " or Cast(EMP_MST.CONTACT_NO As nVarchar(20))= '" + LoginName + "')  " +
                        //           " and EMP_MST.DELETE_FLAG='N' ", commandType: CommandType.Text);
                        //string AssignBy = AssiLoginName.FirstOrDefault();

                        var parmetersMail = new DynamicParameters();
                        parmetersMail.Add("@MAIL_TYPE", "Auto");
                        var MailDetails = await db.QueryAsync<MailDetailsNT>("SP_GET_MAIL_TYPE", parmetersMail, commandType: CommandType.StoredProcedure);

                        string MailBody = "<!DOCTYPE html>\r\n<html>\r\n<head>\r\n    " +
                            "<meta charset=\"UTF-8\">\r\n    " +
                            "<title>QUI Password Reset</title>\r\n</head>" +
                            "\r\n<body style=\"font-family: Arial, sans-serif; font-size: 14px; color: #333;\">\r\n    " +
                            "<p>Dear <strong>" + LoginName + " </strong>,</p>\r\n\r\n    " +
                            "<p>Your password for <strong>QUI</strong> has been successfully reset.</p>\r\n\r\n    " +
                            "<p>Your temporary password is: <strong style=\"color: #d9534f;\">" + TEMPPASSWORD.ToString() + "</strong></p>\r\n\r\n    " +
                            "<p>Please log in to <strong><a href=\"https://qui.piplapps.com\">QUI</a></strong> using this password and update it immediately for security reasons.</p>\r\n\r\n    " +
                            "<p>If you have any questions or need assistance, feel free to contact us at \r\n       " +
                            " <a href=\"mailto:qui.support@powersoft.in\">qui.support@powersoft.in</a>.\r\n    " +
                            "</p>\r\n\r\n    <p>Best regards,<br>\r\n    " +
                            "<strong>QUI Team</strong></p>\r\n</body>\r\n</html>\r\n";

                        foreach (var Mail in MailDetails)
                        {
                            //_commonService.SendEmail(Email, null, null, "FMS-Your Temporary Password", MailBody, "Auto","FMS", null, Mail);  //Mail.MAIL_TYPE
                        }

                        var successsResult = new List<ResetPasswordOutPut_List>
                            {
                                new ResetPasswordOutPut_List
                                {
                                    Status = "Ok",
                                    Message = strMessage,
                                    Data= ResetPass
                                }
                            };
                        return successsResult;
                    }
                    else
                    {
                        var successsResult = new List<ResetPasswordOutPut_List>
                            {
                                new ResetPasswordOutPut_List
                                {
                                    Status = "Error",
                                    Message = strMessage,
                                    Data= null
                                }
                            };
                        return successsResult;
                    }
                }
            }
            catch (Exception ex)
            {
                var errorResult = new List<ResetPasswordOutPut_List>
                    {
                        new ResetPasswordOutPut_List
                        {
                           Status = "Error",
                            Message= ex.Message,
                            Data= null
                        }
                    };
                return errorResult;
            }
        }

        public async Task<IEnumerable<ForgotPasswordOutPut_List>> GetForgotPasswordAsync(string LoginName)
        {
            try
            {
                using (IDbConnection db = _dbConnection.CreateConnection())
                {
                    int ErrorNumber = 0;
                    string ResponseMeaage = string.Empty;
                    var parmeters = new DynamicParameters();
                    parmeters.Add("@LoginName", LoginName);
                    var ForgotPass = await db.QueryAsync<ForgotPasswordOutPut>("Sp_USER_ForgotPassword", parmeters, commandType: CommandType.StoredProcedure);
                    foreach (var SuccessMsg in ForgotPass)
                    {
                        ErrorNumber = SuccessMsg.ErrorNumber;
                        ResponseMeaage = SuccessMsg.MessageText;
                    }
                    if (ErrorNumber != 1)
                    {
                        var ErrorResult = new List<ForgotPasswordOutPut_List>
                        {
                            new ForgotPasswordOutPut_List
                            {
                                Status = "Error",
                                Message = ResponseMeaage,
                                Data= ForgotPass
                            }
                        };
                        return ErrorResult;
                    }
                    else
                    {
                        var successsResult = new List<ForgotPasswordOutPut_List>
                        {
                            new ForgotPasswordOutPut_List
                            {
                                Status = "Ok",
                                Message = "Message",
                                Data= ForgotPass
                            }
                        };
                        return successsResult;
                    }
                }
            }
            catch (Exception ex)
            {
                var errorResult = new List<ForgotPasswordOutPut_List>
                    {
                        new ForgotPasswordOutPut_List
                        {
                           Status = "Error",
                            Message= ex.Message,
                            Data= null
                        }
                    };
                return errorResult;
            }
        }




        #region
        //public async  Task<string> HashPasswordSHA256(string password)
        //{
        //    using (SHA256 sha256Hash = SHA256.Create())
        //    {
        //        // Compute the hash from the password string
        //        byte[] bytes = sha256Hash.ComputeHash(Encoding.UTF8.GetBytes(password));

        //        // Convert the byte array to a hexadecimal string
        //        StringBuilder builder = new StringBuilder();
        //        foreach (var byteValue in bytes)
        //        {
        //            builder.Append(byteValue.ToString("x2"));
        //        }
        //        return builder.ToString();  // Return the hashed password as a string
        //    }
        //}

        // Encrypted Password 
        //public string EncryptPassword(string encryptedPassword, string keyString)
        //{
        //    // Ensure the key is 32 bytes (AES-256) by trimming or padding the key
        //    byte[] key = GetKey(keyString, 32); // AES-256 requires a 32-byte key

        //    using (Aes aesAlg = Aes.Create())
        //    {
        //        aesAlg.Key = key; // Set the AES key
        //        aesAlg.IV = new byte[16]; // Initialization Vector, set to 0 for simplicity (NOT recommended for production)

        //        ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

        //        using (MemoryStream msEncrypt = new MemoryStream())
        //        {
        //            using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
        //            {
        //                using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
        //                {
        //                    swEncrypt.Write(encryptedPassword); // Write the password to be encrypted
        //                }
        //            }

        //            return Convert.ToBase64String(msEncrypt.ToArray()); // Return the encrypted password as a Base64 string
        //        }
        //    }
        //}



        // Encrypted User And Password into One Single Response 


        //public string UserDecryptedResponse(string base64EncryptedData, string keyString)
        //{
        //    try
        //    {
        //        // Decode the Base64 encoded string into a byte array
        //        byte[] encryptedData = Convert.FromBase64String(base64EncryptedData);

        //        // Extract the IV (first 16 bytes) from the encrypted data
        //        byte[] iv = new byte[16];
        //        Buffer.BlockCopy(encryptedData, 0, iv, 0, iv.Length);

        //        // The remaining data is the encrypted content
        //        byte[] cipherText = new byte[encryptedData.Length - iv.Length];
        //        Buffer.BlockCopy(encryptedData, iv.Length, cipherText, 0, cipherText.Length);

        //        // Get the 32-byte key from the key string (Ensure GetKey returns a 32-byte key)
        //        byte[] key = GetKey(keyString, 32);

        //        using (Aes aesAlg = Aes.Create())
        //        {
        //            aesAlg.Key = key;
        //            aesAlg.IV = iv;
        //            aesAlg.Mode = CipherMode.CBC;
        //            aesAlg.Padding = PaddingMode.PKCS7;

        //            ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

        //            using (MemoryStream msDecrypt = new MemoryStream(cipherText))
        //            {
        //                using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
        //                {
        //                    using (StreamReader srDecrypt = new StreamReader(csDecrypt))
        //                    {
        //                        return srDecrypt.ReadToEnd(); // Return the decrypted result as a string
        //                    }
        //                }
        //            }
        //        }
        //    }
        //    catch (Exception ex)
        //    {
        //        throw new InvalidOperationException("An error occurred while decrypting the user data.", ex);
        //    }
        //}

        //public async Task<string> InsertILogResponse(LogResponseObject logResponseObject)
        //{
        //    try
        //    {
        //        if (string.IsNullOrEmpty(logResponseObject.DELETE_FLAG.ToString()) || logResponseObject.DELETE_FLAG == '\0')
        //        {
        //            logResponseObject.DELETE_FLAG = 'N';
        //        }
        //        string storedProcedureName;
        //        storedProcedureName = "[dbo].[UspAddPaymentlogDetails]";
        //        // Create DynamicParameters and add the properties of LogResponseObject
        //        var parameters = new DynamicParameters();
        //        //parameters.Add("@Mkey", logResponseObject.Mkey);  // logResponseObject.Mkey
        //        parameters.Add("@Status", logResponseObject.Status);
        //        parameters.Add("@Message ", logResponseObject.Message);
        //        parameters.Add("@ActionName", logResponseObject.Action_Name);
        //        parameters.Add("@MethodName ", logResponseObject.Method_Name);
        //        parameters.Add("@ATTRIBUTE1 ", logResponseObject.ATTRIBUTE1);
        //        parameters.Add("@ATTRIBUTE2  ", logResponseObject.ATTRIBUTE2);
        //        parameters.Add("@ATTRIBUTE3  ", logResponseObject.ATTRIBUTE3);
        //        parameters.Add("@ATTRIBUTE4  ", logResponseObject.ATTRIBUTE4);
        //        parameters.Add("@ATTRIBUTE5  ", logResponseObject.ATTRIBUT5);
        //        parameters.Add("@CREATION_DATE", logResponseObject.Created_Date);
        //        parameters.Add("@CREATED_BY", logResponseObject.CREATED_BY);
        //        parameters.Add("@LAST_UPDATED_BY", logResponseObject.LAST_UPDATED_BY);
        //        parameters.Add("@LAST_UPDATE_DATE", logResponseObject.LAST_UPDATE_DATE);
        //        parameters.Add("@DELETE_FLAG", logResponseObject.DELETE_FLAG);
        //        parameters.Add("@Payment_Status", logResponseObject.Payment_Status);
        //        parameters.Add("@CF_Payment_ID", logResponseObject.Cf_Payment_Id);
        //        parameters.Add("@Bank_Reference", logResponseObject.Bank_Reference);
        //        parameters.Add("@Entity", logResponseObject.Entity);
        //        parameters.Add("@Is_Captured", logResponseObject.Is_Captured);
        //        parameters.Add("@Order_Amount", logResponseObject.Order_Amount);
        //        parameters.Add("@Order_ID", logResponseObject.Order_Id);
        //        parameters.Add("@Payment_Completion_Time", logResponseObject.Payment_Completion_Time);
        //        parameters.Add("@Payment_Currency", logResponseObject.Payment_Currency);
        //        parameters.Add("@Payment_Message", logResponseObject.Payment_Message);
        //        parameters.Add("@Payment_Method", logResponseObject.Payment_Method);
        //        parameters.Add("@UPI_Channel", logResponseObject.UPI_Channel);
        //        //parameters.Add("@Channel", logResponseObject.Channel);
        //        parameters.Add("@UPI_ID", logResponseObject.Upi_Id);
        //        parameters.Add("@Payment_Time", logResponseObject.Payment_Time);
        //        parameters.Add("@CF_Order_ID", logResponseObject.Cf_Order_Id);
        //        parameters.Add("@Order_Currency", logResponseObject.Order_Currency);
        //        parameters.Add("@Order_Status", logResponseObject.Order_Status);
        //        parameters.Add("@Payment_Session_ID", logResponseObject.Payment_Session_Id);
        //        parameters.Add("@Order_Expiry_Time", logResponseObject.Order_Expiry_Time);
        //        parameters.Add("@Order_Note", logResponseObject.Order_Note);
        //        parameters.Add("@Created_At", logResponseObject.Created_At);
        //        parameters.Add("@Order_Splits", logResponseObject.Order_Splits);
        //        //parameters.Add("@Customer_Details", logResponseObject.Customer_Details);
        //        parameters.Add("@Customer_ID", logResponseObject.Customer_Id);
        //        parameters.Add("@Customer_Email", logResponseObject.Customer_Email);
        //        parameters.Add("@Customer_Phone", logResponseObject.Customer_Phone);
        //        parameters.Add("@Customer_Name", logResponseObject.Customer_Name);
        //        parameters.Add("@Customer_Bank_Account_Number", logResponseObject.Customer_Bank_Account_Number);
        //        parameters.Add("@Customer_Bank_IFSC", logResponseObject.Customer_Bank_Ifsc);
        //        parameters.Add("@Customer_Bank_Code", logResponseObject.Customer_Bank_Code);
        //        parameters.Add("@Customer_UID", logResponseObject.Customer_Uid);
        //        parameters.Add("@Order_Meta", logResponseObject.Order_Meta);
        //        parameters.Add("@Return_URL ", logResponseObject.Return_Url);
        //        parameters.Add("@Notify_URL", logResponseObject.Notify_Url);
        //        parameters.Add("@Payment_Methods", logResponseObject.Payment_Methods);
        //        parameters.Add("@Order_Tags", logResponseObject.Order_Tags);

        //        // Add new settlement fields here as well
        //        parameters.Add("@Settlement_ID", logResponseObject.Settlement_Id);
        //        parameters.Add("@Payment_ID", logResponseObject.Payment_Id);
        //        parameters.Add("@Amount_Settled", logResponseObject.Settlement_Amount);
        //        parameters.Add("@Service_Charge", logResponseObject.Service_Charge);
        //        //parameters.Add("@Payment_Time_Settlement", logResponseObject.Payment_Time_Settlement);
        //        parameters.Add("@Payment_UTR", logResponseObject.Payment_Utr);
        //        parameters.Add("@Remarks ", logResponseObject.Remarks);
        //        //parameters.Add("@Remarks_Settlement", logResponseObject.Remarks_Settlement);
        //        parameters.Add("@Adjustment", logResponseObject.Adjustment);
        //        parameters.Add("@CF_Settlement_ID", logResponseObject.Cf_Settlement_Id);
        //        parameters.Add("@Closed_in_Favor_Of", logResponseObject.Closed_In_Favor_Of);
        //        parameters.Add("@Dispute_Category", logResponseObject.Dispute_Category);
        //        parameters.Add("@Dispute_Note", logResponseObject.Dispute_Note);
        //        parameters.Add("@Dispute_Resolved_On", logResponseObject.Dispute_Resolved_On);
        //        parameters.Add("@Event_Amount", logResponseObject.Event_Amount);
        //        parameters.Add("@Event_Currency", logResponseObject.Event_Currency);
        //        parameters.Add("@Event_Id", logResponseObject.Event_Id);
        //        parameters.Add("@Event_Settlement_Amount", logResponseObject.Event_Settlement_Amount);
        //        parameters.Add("@Event_Status", logResponseObject.Event_Status);
        //        parameters.Add("@Event_Time", logResponseObject.Event_Time);
        //        parameters.Add("@Event_Type", logResponseObject.Event_Type);
        //        parameters.Add("@Payment_Amount", logResponseObject.Payment_Amount);
        //        parameters.Add("@Payment_From", logResponseObject.Payment_From);
        //        parameters.Add("@Payment_Group ", logResponseObject.Payment_Group);
        //        parameters.Add("@Payment_Service_Charge", logResponseObject.Payment_Service_Charge);
        //        parameters.Add("@Payment_Service_Tax", logResponseObject.Payment_Service_Tax);
        //        parameters.Add("@Payment_Till", logResponseObject.Payment_Till);
        //        parameters.Add("@Reason", logResponseObject.Reason);
        //        parameters.Add("@Refund_ARN ", logResponseObject.Refund_Arn);
        //        parameters.Add("@Refund_ID", logResponseObject.Refund_Id);
        //        parameters.Add("@Refund_Note", logResponseObject.Refund_Note);
        //        parameters.Add("@Refund_Processed_At", logResponseObject.Refund_Processed_At);
        //        parameters.Add("@Resolved_On", logResponseObject.Resolved_On);
        //        parameters.Add("@Sale_Type", logResponseObject.Sale_Type);
        //        parameters.Add("@Service_Tax ", logResponseObject.Service_Tax);
        //        parameters.Add("@Settlement_Charge", logResponseObject.Settlement_Charge);
        //        parameters.Add("@Settlement_Date", logResponseObject.Settlement_Date);
        //        parameters.Add("@Settlement_Initiated_On", logResponseObject.Settlement_Initiated_On);
        //        parameters.Add("@Settlement_Tax", logResponseObject.Settlement_Tax);
        //        parameters.Add("@Settlement_Type", logResponseObject.Settlement_Type);
        //        parameters.Add("@Settlement_UTR", logResponseObject.Settlement_Utr);
        //        parameters.Add("@Split_Service_Charge", logResponseObject.Split_Service_Charge);
        //        parameters.Add("@Split_Service_Tax ", logResponseObject.Split_Service_Tax);
        //        //parameters.Add("@Status_Settlement", logResponseObject.Status_Settlement);
        //        parameters.Add("@Vendor_Commission", logResponseObject.Vendor_Commission);
        //        parameters.Add("@Adjustment_Remarks ", logResponseObject.Adjustment_Remarks);
        //        parameters.Add("@ResponseMessage ", dbType: DbType.String, direction: ParameterDirection.Output, size: 500);
        //        // Execute the stored procedure (Insert query using Dapper)
        //        var result = await _connection.ExecuteAsync(storedProcedureName, parameters, commandType: System.Data.CommandType.StoredProcedure);
        //        string responseMessage = parameters.Get<string>("@ResponseMessage ");

        //        // Adjust response message based on MKey value
        //        if (responseMessage.Contains("Success"))
        //        {
        //            // If MKey is 0 (Add), return "Success"
        //            return responseMessage.Contains("Success") ? "Success" : "No rows added";
        //        }
        //        else
        //        {
        //            // If MKey is not 0 (Update), return "Update Success"
        //            return responseMessage.Contains("Success") ? "Update Success" : "No rows updated";
        //        }
        //    }
        //    catch (Exception ex)
        //    {
        //        // Log exception (for your reference or debugging)
        //        return $"Error: {ex.Message}";
        //    }
        //}

        //public async Task<string> LoginRegistration(UserLoginModel userLogin)
        //{
        //    try
        //    {
        //        if (userLogin == null)
        //        {
        //            return "UserLogin is Empty";
        //        }
        //        var keyString = _configuration["EncryptionKey"]; // Retrieve the key from the configuration
        //                                                         //var EncryptedHashPassword = EncryptPassword(userLogin.PasswordHash, keyString);
        //        var parameters = new DynamicParameters();
        //        parameters.Add("@pLogin", userLogin.LoginName);
        //        parameters.Add("@pPassword", userLogin.PasswordHash); // Assuming this is already hashed or encrypted as needed
        //        parameters.Add("@pFirstName", userLogin.FirstName);
        //        parameters.Add("@pLastName", userLogin.LastName);
        //        parameters.Add("@responseMessage", dbType: DbType.String, direction: ParameterDirection.Output, size: 500);
        //        await _connection.ExecuteAsync("dbo.uspAddUser", parameters, commandType: CommandType.StoredProcedure);
        //        string responseMessage = parameters.Get<string>("@responseMessage");
        //        if (!string.IsNullOrEmpty(responseMessage))
        //        {
        //            return "User inserted successfully!";
        //        }
        //        else
        //        {
        //            return "User registration failed.";
        //        }
        //    }
        //    catch (Exception ex)
        //    {
        //        return $"An error occurred: {ex.Message}";
        //    }

        //}


        //public async Task<string> Authenticate(string username, string password)
        //{
        //    var responseMessage = string.Empty;

        //    // Ensure both username and password are provided
        //    if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
        //    {
        //        return "Please Enter Username and Password";
        //    }


        //    var parameters = new DynamicParameters();
        //    parameters.Add("@pLoginName", username);
        //    parameters.Add("@pPassword", password);
        //    parameters.Add("@responseMessage", dbType: DbType.String, direction: ParameterDirection.Output, size: 250); // Output parameter

        //    try
        //    {
        //        await _connection.ExecuteAsync("[dbo].[uspLogin]", parameters, commandType: CommandType.StoredProcedure);

        //        responseMessage = parameters.Get<string>("@responseMessage");

        //        if (responseMessage == "User successfully logged in")
        //        {
        //            // Generate the JWT token
        //            var claims = new[]
        //            {
        //        new Claim(ClaimTypes.Name, username),  // The user's login name
        //        new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()) // Unique identifier for the JWT
        //             };

        //            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:SecretKey"])); // Secret key from configuration
        //            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256); // Signing credentials

        //            var token = new JwtSecurityToken(
        //                issuer: _configuration["Jwt:Issuer"],  // Issuer of the token
        //                audience: _configuration["Jwt:Audience"], // Audience for the token
        //                claims: claims, // Claims associated with the token
        //                expires: DateTime.Now.AddHours(1), // Token expiration time
        //                signingCredentials: creds // Signing credentials
        //            );

        //            // Return the JWT token
        //            return new JwtSecurityTokenHandler().WriteToken(token);
        //        }
        //        else
        //        {
        //            // If authentication failed, return the failure message
        //            return "Invalid login name or password"; // Authentication failed
        //        }
        //    }
        //    catch (Exception ex)
        //    {
        //        // Return any errors that occurred during the process
        //        return $"An error occurred: {ex.Message}";
        //    }
        //}
        #endregion
    }
}
