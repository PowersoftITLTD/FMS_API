using System.Text.Json.Serialization;

namespace FMS_WebAPI.Model
{
    public class UserModel
    {
        public string Username { get; set; }
        public string Password { get; set; }
    }

    public class UserLoginModel
    {
        public int UserId { get; set; }

        public string LoginName { get; set; }

        public string PasswordHash { get; set; }

        public string? FirstName { get; set; }

        public string? LastName { get; set; }


        //public bool IsActive { get; set; }

        //public DateTime CreatedDate { get; set; }

        //public string? ModifiedBy { get; set; }

        //public DateTime? ModifiedDate { get; set; }  
    }

    public class RawJsonModel
    {
        public string PlainText { get; set; }
    }

    public class ObjectUser_Model
    {
        public int Id { get; set; }
        public string Name { get; set; }
        public string Email { get; set; }
    }

    public class ForgotPasswordOutPut_List
    {
        [JsonPropertyName("Status")]
        public string? Status { get; set; }
        [JsonPropertyName("Message")]
        public string? Message { get; set; }

        public IEnumerable<ForgotPasswordOutPut> Data { get; set; }
    }
    public class ForgotPasswordOutPut
    {
        [JsonPropertyName("MessageText")]
        public string? MessageText { get; set; }
        [JsonIgnore]
        public int ErrorNumber { get; set; }
    }
}
