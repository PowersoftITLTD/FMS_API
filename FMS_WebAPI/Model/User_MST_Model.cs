using System.Text.Json.Serialization;

namespace FMS_WebAPI.Model
{
    public class User_MST_Model
    {
        public decimal MKEY { get; set; } // numeric(9,0)
        public string USER_NAME { get; set; } = string.Empty; // nvarchar(510)
        public string LOGIN_NAME { get; set; } = string.Empty; // nvarchar(100)
        public byte[]? PASWORD { get; set; } // varbinary(500)
        public string? EMAIL { get; set; } // nvarchar(500)
        public string? PROJECT_ID { get; set; } // nvarchar(510)
        public string DELETE_FLAG { get; set; } = string.Empty; // char(1)
        public DateTime? EXPIREDATE { get; set; } // datetime
        public decimal? NO_OF_ATTEMPTS { get; set; } // numeric(9,18)
        public string? LOCK_FLAG { get; set; } // char(1)
        public decimal? LOCK_COUNTER { get; set; } // numeric(9,18)
        public DateTime? U_DATETIME { get; set; } // datetime
        public string? RESSET_FLAG { get; set; } // char(1)
        public decimal? LAST_UPDATED_BY { get; set; } // numeric(9,18)
        public DateTime? LAST_UPDATE_DATE { get; set; } // datetime
        public decimal? CREATED_BY { get; set; } // numeric(9,18)
        public DateTime? CREATION_DATE { get; set; } // datetime
        public string? ATTRIBUTE1 { get; set; } // nvarchar(100)
        public string? ATTRIBUTE2 { get; set; } // nvarchar(100)
        public string? ATTRIBUTE3 { get; set; } // nvarchar(100)
        public string? ATTRIBUTE4 { get; set; } // nvarchar(100)
        public string? ATTRIBUTE5 { get; set; } // nvarchar(100)
        public string? FULL_NAME { get; set; } // nvarchar(1000)
        public string? isAdmin { get; set; } // char(1)
    }

    public class ResetPasswordOutPut_List
    {
        [JsonPropertyName("Status")]
        public string? Status { get; set; }
        [JsonPropertyName("Message")]
        public string? Message { get; set; }

        public IEnumerable<ResetPasswordOutPut> Data { get; set; }
    }
    public class ResetPasswordOutPut
    {
        [JsonPropertyName("TEMPPASSWORD")]
        public string? TEMPPASSWORD { get; set; }
        [JsonPropertyName("login_name")]
        public string? login_name { get; set; }
        [JsonPropertyName("EMAIL_ID_OFFICIAL")]
        public string? EMAIL_ID_OFFICIAL { get; set; }
        [JsonIgnore]
        public string? Message { get; set; }
        [JsonIgnore]
        public int ErrorNumber { get; set; }
    }

    public class MailDetailsNT
    {
        [JsonPropertyName("MKEY")]
        public string? MKEY { get; set; }
        [JsonPropertyName("MAIL_TYPE")]
        public string? MAIL_TYPE { get; set; }
        [JsonPropertyName("MAIL_FROM")]
        public string? MAIL_FROM { get; set; }
        [JsonPropertyName("MAIL_DISPLAY_NAME")]
        public string? MAIL_DISPLAY_NAME { get; set; }
        [JsonPropertyName("MAIL_PRIORITY")]
        public string? MAIL_PRIORITY { get; set; }
        [JsonPropertyName("SMTP_PORT")]
        public string? SMTP_PORT { get; set; }
        [JsonPropertyName("SMTP_HOST")]
        public string? SMTP_HOST { get; set; }
        [JsonPropertyName("SMTP_PASS")]
        public string? SMTP_PASS { get; set; }
        [JsonPropertyName("SMTP_ESSL")]
        public string? SMTP_ESSL { get; set; }
        [JsonPropertyName("SMTP_TIMEOUT")]
        public string? SMTP_TIMEOUT { get; set; }
        [JsonPropertyName("MAIL1")]
        public string? MAIL1 { get; set; }
        [JsonPropertyName("MAIL2")]
        public string? MAIL2 { get; set; }
        [JsonPropertyName("MAIL3")]
        public string? MAIL3 { get; set; }
        [JsonPropertyName("CREATED_BY")]
        public string? CREATED_BY { get; set; }
        [JsonPropertyName("CREATION_DATE")]
        public string? CREATION_DATE { get; set; }
        [JsonPropertyName("LAST_UPDATE_DATE")]
        public string? LAST_UPDATE_DATE { get; set; }
        [JsonPropertyName("LAST_UPDATED_BY")]
        public string? LAST_UPDATED_BY { get; set; }
        [JsonPropertyName("DELETE_FLAG")]
        public string? DELETE_FLAG { get; set; }
        [JsonPropertyName("ATTRIBUTE1")]
        public string? ATTRIBUTE1 { get; set; }
        [JsonPropertyName("ATTRIBUTE2")]
        public string? ATTRIBUTE2 { get; set; }
    }
    public class HostEnvironment
    {
        public string env { get; set; }
    }
    public class FileSettings
    {
        public string FilePath { get; set; }
    }
}
