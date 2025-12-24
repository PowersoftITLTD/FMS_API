using Dapper;
using FMS_WebAPI.Model;
using FMS_WebAPI.Repository.IRepositoryService;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
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
        private readonly FileSettings _fileSettings;
        private readonly string keyString;
        //const string APIKEY = "PSOFT-API-KEY";
        //const string APIKEYVALUE = "5D5KVRahTIZ5brjKSXmsktmUAK";
        public AuthController(IAuthService authService, SqlConnection sqlConnection, IConfiguration configuration, IDapperDbConnection dapperConnection, ICommonService commonService ,IOptions<FileSettings> fileSetting)
        {
            _authService = authService;
            _configuration = configuration;
            _dapperConnection = dapperConnection;
            _commonService = commonService;
            _fileSettings = fileSetting.Value;
            keyString = _configuration["EncryptionKey"];
        }

        [HttpPost("ValidateLogin")]
        public async Task<IActionResult> Login([FromBody] User userModel)
        {
            //var keyString = _configuration["EncryptionKey"];
            var APIKEYVALUE = _configuration["APIKEYVALUE"];
            var APIKEY = _configuration["APIKEY"];
            var responseObject = new ResponseObject<object>();

            try
            {
                //var receivedKey = Request.Headers[APIKEYVALUE].FirstOrDefault(); 
                //if (string.IsNullOrEmpty(receivedKey) || receivedKey != APIKEY) 
                //{ 
                //    return Unauthorized(new { message = "Unauthorized or invalid API key" }); 
                //}
                var userModels = new UserModel
                {
                    Username = userModel.username,
                    Password = userModel.password
                };
                var validate_obj = await _authService.GetCheckUserName_PasswordVerifying(userModels);
                if (validate_obj.Status == "Failed" && validate_obj.flag_Status== false)
                {
                    responseObject.Status = "Error";
                    responseObject.Message = validate_obj.Message;
                    responseObject.Data = null;
                    return Ok(responseObject);
                }
                else
                {
                    var response = await _authService.ValidateLogin(userModel);
                    var UserEncrypted = _authService.UserEncryptedReponsone(userModel, keyString);
                    var UserDetailsEncrypted = _commonService.EncryptionObje<UserDetailsModel>(response.User, keyString);
                    var UserwareHouseDetailsEncrypted = _commonService.EncryptionObje<List<WarehouseModel>>(response.Warehouses, keyString);
                    var UserDetailsDeEncrypted = _commonService.DecryptObject<UserDetailsModel>(UserDetailsEncrypted, keyString);
                    var UserWareHouseDetailsDeEncrypted = _commonService.DecryptObject<List<WarehouseModel>>(UserwareHouseDetailsEncrypted, keyString);
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
                    responseObject.Data = new { ToKen = response.Token, user = UserDetailsEncrypted, warehouses = UserwareHouseDetailsEncrypted, UserEncryptedDetails = UserEncrypted };
                    return Ok(responseObject);

                }
            }
            catch (Exception ex)
            {
                responseObject.Status = "Error";
                responseObject.Message = "An error occurred during login/registration.";
                responseObject.Data = new { error = ex.Message };
                return StatusCode(StatusCodes.Status500InternalServerError, responseObject);
            }
        }

        [HttpPost("Login_NT")]
        public async Task<IActionResult> EncryptedLogin_User([FromBody] EncryptedLogin_Model encryptedLogin)
        {
            var responseObject = new ResponseObject<object>();
            var userModel = new UserModel();
            try
            {
                //var Passwordhash = Convert.ToByte(Password);
                //var keyString = _configuration["EncryptionKey"];
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
                var validate_obj = await _authService.GetCheckUserName_PasswordVerifying(userModel);
                if (validate_obj.Status == "Failed" && validate_obj.flag_Status == false)
                {
                    responseObject.Status = "Error";
                    responseObject.Message = validate_obj.Message;
                    responseObject.Data = null;
                    return Ok(responseObject);
                }
                else
                {
                    var result = await _authService.VerifyingResponse(userModel.Username.ToLower(), userModel.Password);
                    var userNameCom = userModel.Username + ":" + userModel.Password;
                    var userDetails = _commonService.EncryptionObje(result.User, keyString);
                    var WareHouseDetails = _commonService.EncryptionObje(result.Warehouses, keyString);
                    //string encryptedUser = _commonService.EncryptionObje(userNameCom, keyString);
                    if (!string.IsNullOrEmpty(result.User.EMAIL) && (!string.IsNullOrEmpty(result.User.LOGIN_NAME)))
                    {
                        responseObject.Status = "Ok";
                        responseObject.Message = "User successfully Decrypted logged in Credential";
                        responseObject.Data = new { token = result.Token, User = userDetails, WareHouse = WareHouseDetails };// encryptedUser;//result;
                        var Dcs = _commonService.DecryptObject<UserDetailsModel>(userDetails, keyString);
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

        [HttpPost("WMSBarCode-Login/Registration")]
        public async Task<IActionResult> LoginRegistration(DeviceRegistration deviceRegistration)
        {
            var responseObject = new ResponseObject<object>();
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
                    responseObject.Data = result;
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
        [HttpPost("WMSBarCode-ValidateLoginWithWHCode")]
        public async Task<IActionResult> ValidateLoginWithWHCode([FromBody] UserWarehouseCode userwareHouse)
        {
            //var keyString = _configuration["EncryptionKey"];
            var APIKEYVALUE = _configuration["APIKEYVALUE"];
            var APIKEY = _configuration["APIKEY"];
            var responseObject = new ResponseObject<object>();
            try
            {
                //var receivedKey = Request.Headers[APIKEYVALUE].FirstOrDefault();
                //if (string.IsNullOrEmpty(receivedKey) || receivedKey != APIKEY)
                //{
                //    return Unauthorized(new { message = "Unauthorized or invalid API key" });
                //}
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

        [Authorize]
        [HttpPost("WMSBarCode-ValidateLoginWithWHCode_NT")]
        public async Task<IActionResult> ValidateLoginWithWHCode_NT([FromBody] UserWarehouseCode userwareHouse)    //[FromBody] UserWarehouseCode userwareHouse   // CommonEncryptRsw commonEncryptRsw
        {
            //var keyString = _configuration["EncryptionKey"];
            var APIKEYVALUE = _configuration["APIKEYVALUE"];
            var APIKEY = _configuration["APIKEY"];
            var responseObject = new ResponseObject<object>();
            try
            {
                CommonEncryptRsw commonEncryptRsw = new CommonEncryptRsw
                {
                    encryptjosn = _commonService.EncryptionObje(userwareHouse, keyString)
                };
                //var receivedKey = Request.Headers[APIKEYVALUE].FirstOrDefault();
                //if (string.IsNullOrEmpty(receivedKey) || receivedKey != APIKEY)
                //{
                //    return Unauthorized(new { message = "Unauthorized or invalid API key" });
                //}
                if (string.IsNullOrEmpty(commonEncryptRsw.encryptjosn))
                {
                    responseObject.Status = "Error";
                    responseObject.Message = "Please provide valid encrypted data.";
                    return Ok(responseObject);
                }
                else
                {
                    var userwareHouses = _commonService.DecryptObject<UserWarehouseCode>(commonEncryptRsw.encryptjosn, keyString);
                    var response = await _authService.ValidateLogin_WHCode(userwareHouses);
                    var userModel = new User
                    {
                        username = userwareHouses.username,
                        password = userwareHouses.password,
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

        [Authorize]
        [HttpPost("WMSBarCode-GetWarehouseDetails")]
        public async Task<IActionResult> GetWarehouseDetails([FromBody]WarehouseDetails warehouse)
        {
            //var keyString = _configuration["EncryptionKey"];
            var APIKEYVALUE = _configuration["APIKEYVALUE"];
            var APIKEY = _configuration["APIKEY"];
            var responseObject = new ResponseObject<object>();
            try
            {
                //var receivedKey = Request.Headers[APIKEYVALUE].FirstOrDefault();
                //if (string.IsNullOrEmpty(receivedKey) || receivedKey != APIKEY)
                //{
                //    return Unauthorized(new { message = "Unauthorized or invalid API key" });
                //}
                var resultresponse = await _authService.GetWarehouseDetails(warehouse);
                var encryptedobj =  _commonService.EncryptionObje(resultresponse.Data, keyString);
                if (resultresponse.Status == "Success")
                {
                    var forgetPaswordModel =  _commonService.DecryptObject<List<WarehouseDetails_Model>>(encryptedobj, keyString);
                    return Ok(forgetPaswordModel);
                }
                else
                {
                    return Ok(encryptedobj);
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
        [HttpPost("WMSBarCode-GetWarehouseDetails_NT")]
        public async Task<IActionResult> GetWarehouseDetails_NT([FromBody] CommonEncryptRsw commonEncryptRsw)  // WarehouseDetails warehouse  //CommonEncryptRsw commonEncryptRsw
        {
           // var keyString = _configuration["EncryptionKey"];
            var APIKEYVALUE = _configuration["APIKEYVALUE"];
            var APIKEY = _configuration["APIKEY"];
            var responseObject = new ResponseObject<object>();
            try
            {
                ////CommonEncryptRsw commonEncryptRsw = new CommonEncryptRsw
                ////{
                ////    encryptjosn = _commonService.EncryptionObje(warehouse, keyString)
                ////};
                //var receivedKey = Request.Headers[APIKEYVALUE].FirstOrDefault();
                //if (string.IsNullOrEmpty(receivedKey) || receivedKey != APIKEY)
                //{
                //    return Unauthorized(new { message = "Unauthorized or invalid API key" });
                //}

                if (string.IsNullOrEmpty(commonEncryptRsw.encryptjosn))
                {
                    responseObject.Status = "Error";
                    responseObject.Message = "Please provide valid encrypted data.";
                    return Ok(responseObject);
                }
                else
                {
                    var warehouses = _commonService.DecryptObject<WarehouseDetails>(commonEncryptRsw.encryptjosn, keyString);
                    var resultresponse = await _authService.GetWarehouseDetails(warehouses);

                    if (resultresponse.Status == "Success")
                    {
                        var encryptedobj = _commonService.EncryptionObje(resultresponse.Data, keyString);
                        //var forgetPaswordModel = _commonService.DecryptObject<List<WarehouseDetails_Model>>(encryptedobj, keyString);
                        return Ok(encryptedobj);
                    }
                    else
                    {
                        var encryptedobj = _commonService.EncryptionObje(resultresponse.Data, keyString);
                        return Ok(encryptedobj);
                    }
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
        public async Task<IActionResult> GetLocationDetails([FromBody]WarehouseDetails warehouse)
        {
            //var keyString = _configuration["EncryptionKey"];
            var APIKEYVALUE = _configuration["APIKEYVALUE"];
            var APIKEY = _configuration["APIKEY"];
            var responseObject = new ResponseObject<object>();
            try
            {
                //var receivedKey = Request.Headers[APIKEYVALUE].FirstOrDefault();
                //if (!string.IsNullOrEmpty(warehouse.warehouseid) || warehouse.warehouseid != null))
                //{
                //    return Unauthorized(new { message = "Unauthorized or invalid API key" });
                //}
                var resultresponse = await _authService.GetLocationDetails(warehouse);
                var encryptedobj = _commonService.EncryptionObje(resultresponse.Data, keyString);
                if (resultresponse.Status == "Success")
                {
                    var forgetPaswordModel = _commonService.DecryptObject<List<LocationDetails_Model>>(encryptedobj, keyString);
                    return Ok(encryptedobj);
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
        // New Update Version Api With _NT 
        [Authorize]
        [HttpPost("WMSBarCode-GetLocationDetails_NT")]
        public async Task<IActionResult> GetLocationDetails_NT([FromBody] WarehouseDetails warehouse)  // WarehouseDetails warehouse
        {
           // var keyString = _configuration["EncryptionKey"];
            var APIKEYVALUE = _configuration["APIKEYVALUE"];
            var APIKEY = _configuration["APIKEY"];
            var responseObject = new ResponseObject<object>();
            try
            {
                CommonEncryptRsw commonEncryptRsw = new CommonEncryptRsw
                {
                    encryptjosn = _commonService.EncryptionObje(warehouse, keyString)
                };
                //var receivedKey = Request.Headers[APIKEYVALUE].FirstOrDefault();
                //if (!string.IsNullOrEmpty(warehouse.warehouseid) || warehouse.warehouseid != null))
                //{
                //    return Unauthorized(new { message = "Unauthorized or invalid API key" });
                //}
                if (string.IsNullOrEmpty(commonEncryptRsw.encryptjosn))
                {
                    responseObject.Status = "Error";
                    responseObject.Message = "Please provide valid encrypted data.";
                    return Ok(responseObject);
                }
                else
                {
                    var warehouses = _commonService.DecryptObject<WarehouseDetails>(commonEncryptRsw.encryptjosn, keyString);
                    var resultresponse = await _authService.GetLocationDetails(warehouses);
                    var encryptedobj = _commonService.EncryptionObje(resultresponse.Data, keyString);
                    if (resultresponse.Status == "Success")
                    {
                        var forgetPaswordModel = _commonService.DecryptObject<List<LocationDetails_Model>>(encryptedobj, keyString);
                        return Ok(encryptedobj);
                    }
                    else
                    {
                        return Ok(encryptedobj);
                    }
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

        [HttpPost("ForgetPassword_NT")]
        public async Task<IActionResult> ForgetPassword([FromBody] CommonEncryptRsw encryptRsw)
        {
            var responseObject = new ResponseObject<object>();
            var userModel = new UserModel();
            try
            {
                //var Passwordhash = Convert.ToByte(Password);
               // var keyString = _configuration["EncryptionKey"];
                //string encryptedUser = _commonService.EncryptionObje(encryptRsw.encryptjosn, keyString);
                var forgetPaswordModel = _commonService.DecryptObject<string>(encryptRsw.encryptjosn, keyString);  //encryptRsw.encryptjosn
                //var PassworsHash = _authService.DecryptPassword(changesPassword.changePassword, keyString);
                //if (PassworsHash != null)
                //{
                //    string[] strDatat = PassworsHash.Split(':');
                //    if (strDatat.Length >= 0)
                //    {
                //        userModel = new UserModel
                //        {
                //            Username = strDatat[0],
                //            Password = strDatat[1]
                //        };
                //    }
                //}

                var user_Mst_details = await _authService.GetuserDetails_ByEmailId(forgetPaswordModel);

                var ForgotPass = await _authService.GetForgotPasswordAsync(forgetPaswordModel);

                if (ForgotPass == null)
                {
                    var responseTaskAction = new ResponseObject<object>
                    {
                        Status = "Error",
                        Message = "Error Occurd",
                        Data = null
                    };
                    return Ok(responseTaskAction);
                }
                if (forgetPaswordModel == null)
                {
                    var responseTaskAction = new ResponseObject<object>
                    {
                        Status = "Error",
                        Message = "Error Occurd LoginName",
                        Data = null
                    };
                    return Ok(responseTaskAction);
                }
                foreach (var Response in ForgotPass)
                {
                    if (Response.Status != "Ok")
                    {
                        var response = new ResetPasswordOutPut_List
                        {
                            Status = "Error",
                            Message = Response.Message,
                            Data = null
                        };
                        return Ok(response);
                    }
                }
                string TempararyPass = string.Empty;
                foreach (var TempPaass in ForgotPass)
                {
                    TempararyPass = TempPaass.Data.Select(x => x.MessageText.ToString()).First().ToString();
                }

                var ResetPass = await _authService.GetResetPasswordAsync(TempararyPass, forgetPaswordModel);

                if (ResetPass == null)
                {
                    var responseTaskAction = new ResponseObject<object>
                    {
                        Status = "Error",
                        Message = "Error Occurd",
                        Data = null
                    };
                    return Ok(responseTaskAction);
                }
                else
                {
                    var ResetpasswordData = ResetPass.Select(x => x.Data).FirstOrDefault();
                    string encryptedUser = _commonService.EncryptionObje(ResetpasswordData, keyString);
                    //var DESc = _commonService.DecryptObject<string>(encryptedUser, keyString);  // This Part for Decrypt the Data only For Testing
                    var responseTaskAction = new ResponseObject<object>
                    {
                        Status = "Ok",
                        Message = "Password Reset Successfully",
                        Data = encryptedUser
                    };
                    return Ok(responseTaskAction);
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

        // Changes Password Started
        [Authorize]
        [HttpPost("ChangesPassword_NT")]
        public async Task<IActionResult> ChangePassword([FromBody] ChangesPasswordEncrypt_Model changesPassword)  //ChangesPasswordEncrypt_Model
        {
            var responseObject = new ResponseObject<object>();
            var userModel = new UserModel();
            try
            {
                //var Passwordhash = Convert.ToByte(Password);
                //var keyString = _configuration["EncryptionKey"];
                //string encryptedUser = _commonService.EncryptionObje(changesPassword, keyString); // Adding for Encrypted Data 
                var changePaswordModel = _commonService.DecryptObject<ChangePassword_Model>(changesPassword.changePassword, keyString);
                //var changePaswordModel = _commonService.DecryptObject<ChangePassword_Model>(encryptedUser, keyString);
                //var PassworsHash = _authService.DecryptPassword(changesPassword.changePassword, keyString);
                //if (PassworsHash != null)
                //{
                //    string[] strDatat = PassworsHash.Split(':');
                //    if (strDatat.Length >= 0)
                //    {
                //        userModel = new UserModel
                //        {
                //            Username = strDatat[0],
                //            Password = strDatat[1]
                //        };
                //    }
                //}
                var result = await _authService.ChangePassword(changePaswordModel);
                if (result.Status.Contains("Success") && (result.Message.Contains("Updated Successfully")))
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

        [Authorize]
        [HttpGet("UserDecryptedPasswordVerifying")]
        public async Task<IActionResult> UserDecryptedPasswordVerifying([FromBody]string Password)
        {
            var responseObject = new ResponseObject<object>();
            var userModel = new UserModel();
            try
            {
                //var Passwordhash = Convert.ToByte(Password);
                //var keyString = _configuration["EncryptionKey"];
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
                var result = await _authService.VerifyingResponse(userModel.Username.ToLower(), userModel.Password);
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

        // File Decryption method Here 
        //[Authorize]
        //[HttpPost("Upload-File_NT")]
        //public async Task<IActionResult> UploadEncryptedFile([FromBody] EncryptedFileDto dto)
        //{
        //    try
        //    {
        //        var key = _configuration["EncryptionKey"];

        //        // Decrypt file bytes
        //        byte[] fileBytes =_commonService.DecryptFileBytes(dto.EncryptedData, key);

        //        // Create folder
        //        string folderPath = Path.Combine("D:\\Uploads\\EncryptedFiles");
        //        if (!Directory.Exists(folderPath))
        //            Directory.CreateDirectory(folderPath);

        //        // Full file path
        //        string filePath = Path.Combine(folderPath, dto.FileName);

        //        // Save file
        //        await System.IO.File.WriteAllBytesAsync(filePath, fileBytes);

        //        // Save path in DB
        //        //SavePathToDB(dto.FileName, filePath);

        //        Response.Headers.Add("Content-Disposition", $"attachment; filename=\"{dto.FileName}\"");
        //        return File(fileBytes, "application/octet-stream", dto.FileName);

        //        //return Ok(new { message = "File uploaded successfully", filePath });
        //    }
        //    catch (Exception ex)
        //    {
        //        return BadRequest(ex.Message);
        //    }
        //}

        //// Encrypt The Object and list Of Object 
        //[HttpGet("Encrypt-GetConvertEncryptionKey_TEST")]
        //[NonAction]
        //public async Task<IActionResult> GetConvertEncryptionKey()
        //{
        //    try
        //    {
        //        var user = new ObjectUser_Model { Id = 1, Name = "Amit", Email = "amit@example.com" };
        //        string encryptionKey = _configuration["EncryptionKey"];

        //        string encryptedUser = _commonService.EncryptionObje(user, encryptionKey);

        //        var usersList = new List<ObjectUser_Model>
        //        {
        //          new ObjectUser_Model{ Id=1, Name="Amit", Email="amit@example.com" },
        //          new ObjectUser_Model{ Id=2, Name="Neha", Email="neha@example.com" }
        //       };

        //        string encryptedList = _commonService.EncryptionObje(usersList, encryptionKey);

        //        if (!string.IsNullOrEmpty(encryptedUser))
        //        {
        //            var userModel= _commonService.DecryptObject<ObjectUser_Model>(encryptedUser, encryptionKey);
        //            var userModelList = _commonService.DecryptObject<List<ObjectUser_Model>>(encryptedList, encryptionKey);
        //            //var userModelList = DecryptObject<ObjectUser_Model>(encryptedList, encryptionKey);
        //            return Ok(new { Status = "Success", EncryptedData = encryptedUser , Message= "Data Fetch Successfully" ,Decrypted= userModel , DecryptedList = userModelList });
        //        }
        //        else
        //        {
        //            return Ok(new { Status = "Success", EncryptedData = encryptedUser, Message = "No Data Available" });
        //        }
               
        //    }
        //    catch(Exception ex)
        //    {
        //        return BadRequest(ex.Message);
        //    }
        //}

        //[HttpPost("EncryptFileToBase64Async")]
        ////[HttpPost("EncryptFile")]
        //public async Task<IActionResult> EncryptFile(IFormFile file)
        //{
        //    if (file == null || file.Length == 0)
        //        return BadRequest("No file selected");
        //    var response = new DocumentUploadModel();
        //    try
        //    {
        //        // Read file bytes
        //        byte[] fileBytes;
        //        using (var ms = new MemoryStream())
        //        {
        //            await file.CopyToAsync(ms);
        //            fileBytes = ms.ToArray();
        //        }

        //        // Encrypt bytes using zero IV (to match Angular)
        //        string key = _configuration["EncryptionKey"];
        //        string _filePath = _configuration["FileSettings:FilePath"];

        //        byte[] keyBytes = GetKey(key, 32); // 32 bytes for AES-256
        //        byte[] iv = new byte[16]; // zero IV

        //        using var aes = Aes.Create();
        //        aes.Key = keyBytes;
        //        aes.IV = iv;
        //        aes.Mode = CipherMode.CBC;
        //        aes.Padding = PaddingMode.PKCS7;

        //        using var encryptor = aes.CreateEncryptor();
        //        byte[] cipherBytes = encryptor.TransformFinalBlock(fileBytes, 0, fileBytes.Length);

        //        //// Convert encrypted bytes to Base64 string
        //        //string encryptedBase64 = Convert.ToBase64String(cipherBytes);

        //        //byte[] fileBytess = _commonService.DecryptFileBytes(encryptedBase64, key);

        //        //// Encrypt The FileByte 
        //        var encryptfileByte = _commonService.EncryptBytes(cipherBytes, key);

        //        // Create folder
        //        string folderPath = Path.Combine(_filePath);
        //        if (!Directory.Exists(folderPath))
        //            Directory.CreateDirectory(folderPath);

        //        // Full file path
        //        string filePath = Path.Combine(folderPath, file.FileName);

        //        // Save file
        //        await System.IO.File.WriteAllBytesAsync(filePath, fileBytes);



        //        // Save path in DB
        //        //SavePathToDB(dto.FileName, filePath);

        //        //Response.Headers.Add("Content-Disposition", $"attachment; filename=\"{dto.FileName}\"");
        //       // return File(fileBytes, "application/octet-stream", dto.FileName);
        //        return Ok(new { FileName = file.FileName,_fileByte= encryptfileByte }); //, EncryptedData = encryptedBase64  
        //    }
        //    catch (Exception ex)
        //    {
        //        return BadRequest(ex.Message);
        //    }
        //}

        [HttpPost("EncryptFileToBase64Async")]
        //[HttpPost("EncryptFile")]
        public async Task<IActionResult> EncryptFile([FromBody] string strJson)  //IFormFile file
        {
            //if (file == null || file.Length == 0)
            //    return BadRequest("No file selected");

            try
            {
                //if (file == null || file.Length == 0)
                //{
                //    return BadRequest("No file selected");
                //}

                // Convert file to byte array
                //byte[] fileBytes;
                //using (var memoryStream = new MemoryStream())
                //{
                //    file.CopyTo(memoryStream);
                //    fileBytes = memoryStream.ToArray();
                //}
                //string fileAsBase64 = Convert.ToBase64String(fileBytes);
                byte[] bytesFromBase64 = Convert.FromBase64String(strJson);  //fileAsBase64
                // Return the file as a downloadable file
                //return Ok(new
                //{
                //    Message = "File converted to string and ready to save",
                //    FileName = file.FileName,
                //    FileData = fileAsBase64 , // Optional: return Base64 string
                //    FileContentType = file.ContentType
                //});
                //return File(bytesFromBase64, file.ContentType, file.FileName);
                return File(bytesFromBase64, "text/plain", "CLI commands.txt");




            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }

        // Helper method for key derivation
        private static byte[] GetKey(string keyString, int length)
        {
            byte[] keyBytes = Encoding.UTF8.GetBytes(keyString);
            if (keyBytes.Length > length)
                Array.Resize(ref keyBytes, length);
            else if (keyBytes.Length < length)
                keyBytes = keyBytes.Concat(new byte[length - keyBytes.Length]).ToArray();
            return keyBytes;
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
