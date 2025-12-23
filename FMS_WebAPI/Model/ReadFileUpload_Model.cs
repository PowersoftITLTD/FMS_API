using System.Text.Json.Serialization;

namespace FMS_WebAPI.Model
{
    public class ReadFileUpload_Model
    {
        public int Identifier { get; set; }
        public int SrNo { get; set; }
        public string? fileName { get; set; }
    }

    public class FileUploadResultModel
    {
        public int MKey { get; set; }
        public string FileName { get; set; }
        public string Base64File { get; set; } // PDF encoded as Base64 string
        public string ContentType { get; set; }
    }

    public class DocumentUploadModel
    {
        [JsonPropertyName("mkey")]
        public decimal MKEY { get; set; }
        [JsonPropertyName("sR_NO")]
        public decimal SR_NO { get; set; }
        [JsonPropertyName("doC_NAME")]
        public string DOC_NAME { get; set; } = string.Empty;

        [JsonPropertyName("doC_TYPE")]
        public string? DOC_TYPE { get; set; }
        [JsonPropertyName("filE_NAME")]
        public string? FILE_NAME { get; set; }

        // VARBINARY(MAX)
        //public byte[]? FILECONTENTS { get; set; }
        //public List<IFormFile> FILECONTENTS { get; set; }
        [JsonPropertyName("filecontents")]
        public string? FILECONTENTS { get; set; }
        [JsonPropertyName("filecontentvar")]
        public string? FILECONTENTVAR { get; set; }
        //public string? FileContentType { get; set; }
        [JsonPropertyName("uploadeD_BY")]
        public decimal? UPLOADED_BY { get; set; }
        [JsonPropertyName("uploaD_DATE")]
        public DateTime? UPLOAD_DATE { get; set; }
        [JsonPropertyName("iS_MANDATORY")]
        public string? IS_MANDATORY { get; set; }   // Y / N
        [JsonPropertyName("statuS_FLAG")]
        public string? STATUS_FLAG { get; set; }    // A / P / R etc.
        [JsonPropertyName("approveR_ID")]
        public decimal? APPROVER_ID { get; set; }
        [JsonPropertyName("approvE_ACTION_DATE")]
        public string? APPROVE_ACTION_DATE { get; set; }

        [JsonPropertyName("attributE1")]
        public string? ATTRIBUTE1 { get; set; }
        [JsonPropertyName("attributE2")]
        public string? ATTRIBUTE2 { get; set; }
        [JsonPropertyName("attributE3")]
        public string? ATTRIBUTE3 { get; set; }
        [JsonPropertyName("attributE4")]
        public string? ATTRIBUTE4 { get; set; }
        [JsonPropertyName("attributE5")]
        public string? ATTRIBUTE5 { get; set; }
        [JsonPropertyName("createD_BY")]
        public decimal CREATED_BY { get; set; }
        [JsonPropertyName("creatioN_DATE")]
        public DateTime? CREATION_DATE { get; set; }
        [JsonPropertyName("lasT_UPDATED_BY")]
        public decimal? LAST_UPDATED_BY { get; set; }
        [JsonPropertyName("lasT_UPDATE_DATE")]
        public DateTime? LAST_UPDATE_DATE { get; set; }
        [JsonPropertyName("deletE_FLAG")]
        public string DELETE_FLAG { get; set; } = "N";
    }
    public class EncryptedFile_Dto
    {
        public string FileName { get; set; }
        public byte[] FileBytes { get; set; }
    }
    public class DocumentUploadCryptoDto
    {
        public decimal MKEY { get; set; }
        public decimal SR_NO { get; set; }
        public string DOC_NAME { get; set; }
        public string DOC_TYPE { get; set; }
        public string? FILE_NAME { get; set; }
        public List<EncryptedFile_Dto> Files { get; set; } = new();

        public decimal? UPLOADED_BY { get; set; }
        public DateTime? UPLOAD_DATE { get; set; }

        public string? IS_MANDATORY { get; set; }   // Y / N
        public string? STATUS_FLAG { get; set; }    // A / P / R etc.

        public decimal? APPROVER_ID { get; set; }
        public DateTime? APPROVE_ACTION_DATE { get; set; }

        public string? ATTRIBUTE1 { get; set; }
        public string? ATTRIBUTE2 { get; set; }
        public string? ATTRIBUTE3 { get; set; }
        public string? ATTRIBUTE4 { get; set; }
        public string? ATTRIBUTE5 { get; set; }

        public decimal CREATED_BY { get; set; }
        public DateTime CREATION_DATE { get; set; }
        public decimal? LAST_UPDATED_BY { get; set; }
        public DateTime? LAST_UPDATE_DATE { get; set; }

        public string DELETE_FLAG { get; set; }
    }
    public class DocumentInsertResponse
    {
        public string Status { get; set; }
        public string Message { get; set; }
        public long? MKEY { get; set; }
        public long? SR_NO { get; set; }
    }
}
