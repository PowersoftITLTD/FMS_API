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
        Task<ResponseObject> GetWarehouseDetails(WarehouseDetails warehouseModel);
        Task<ResponseObject> GetLocationDetails(WarehouseDetails warehouseDetails);
        Task<ResponseObject> WMSBarCode_Registration(DeviceRegistration _devicereg);
        //Task<string> InsertILogResponse(LogResponseObject logResponseObject);

        //string UserDecryptedResponse(string encryptedData, string keyString);
    }
}
