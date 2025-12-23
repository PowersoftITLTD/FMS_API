using FMS_WebAPI.Model;

namespace FMS_WebAPI.Repository.IRepositoryService
{
    public interface IAuthService
    {
        //Task<string> Authenticate(string username, string password);
        Task<LoginResponse> ValidateLogin(User _user);
        Task<string> LoginRegistration(UserLoginModel userLogin);
        string DecryptPassword(string encryptedPassword, string keyString);
        byte[] UserEncryptedReponsone(User userModel, string keyString);
        Task<int> GetUserIdbyUserName(string userName);
        Task<LoginResponse> VerifyingResponse(string userLogin, string Password);

        Task<LoginResponse> ValidateLogin_WHCode(UserWarehouseCode _userWarehouse);
        Task<ResponseObject<List<WarehouseDetails_Model>>> GetWarehouseDetails(WarehouseDetails warehouseModel);
        Task<ResponseObject<List<LocationDetails_Model>>> GetLocationDetails(WarehouseDetails warehouseDetails);
        Task<ResponseObject<dynamic>> WMSBarCode_Registration(DeviceRegistration _devicereg);
        Task<ResponseObject<string>> ChangePassword(ChangePassword_Model changePassword);
        Task<ResponseObject<List<User_MST_Model>>> GetuserDetails_ByEmailId(string email);
        Task<IEnumerable<ForgotPasswordOutPut_List>> GetForgotPasswordAsync(string LoginName);
        Task<IEnumerable<ResetPasswordOutPut_List>> GetResetPasswordAsync(string TEMPPASSWORD, string LoginName);
        Task<ResponseVerifying_Validate> GetCheckUserName_PasswordVerifying(UserModel userModel);

        //Task<string> InsertILogResponse(LogResponseObject logResponseObject);

        //string UserDecryptedResponse(string encryptedData, string keyString);
    }
}
