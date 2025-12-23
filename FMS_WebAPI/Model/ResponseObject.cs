using System.Data;

namespace FMS_WebAPI.Model
{
    public class ResponseObject<T>
    {
        public string Status { get; set; }
        public string Message { get; set; }
        public T Data { get; set; } // You can make Data generic if needed
    }

    public class EncryptedPayload
    {
        public string Payload { get; set; }
    }

    public class User
    {
        public string username { get; set; }
        public string password { get; set; }
        public int warehouseid { get; set; }
    }
    public class WarehouseModel
    {
        public int WarehouseId { get; set; }
        public string WarehouseName { get; set; }
    }

    public class UserDetailsModel
    {
        public int MKEY { get; set; }
        public string USER_NAME { get; set; }
        public string LOGIN_NAME { get; set; }
        public string EMAIL { get; set; }
        public string DELETE_FLAG { get; set; }
    }
    public class LoginResponse
    {
        public UserDetailsModel User { get; set; }
        public List<WarehouseModel> Warehouses { get; set; } = new();
        public string Token { get; set; }
        public string Error { get; set; }
    }

    public class ResponseVerifying_Validate
    {
        public string Status { get; set; }
        public string Message { get; set; }
        public bool flag_Status { get; set;}
    }
}
