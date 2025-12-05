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
}
