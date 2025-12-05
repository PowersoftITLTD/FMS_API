using System.Web.Http;

namespace FMS_WebAPI.Model
{
    public class UserWarehouseCode
    {
        [HttpBindRequired]
        public string username { get; set; }
        [HttpBindRequired]
        public string password { get; set; }
        [HttpBindRequired]
        public string warehousecode { get; set; }
    }

    public class WarehouseDetails
    {
        public string userid { get; set; }
        public string warehouseid { get; set; }
    }

    public class DeviceRegistration
    {
        [HttpBindRequired]
        public string deviceid { get; set; }

        [HttpBindRequired]
        public string warehousecode { get; set; }
    }
}
