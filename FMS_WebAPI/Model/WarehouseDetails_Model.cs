namespace FMS_WebAPI.Model
{
    public class WarehouseDetails_Model
    {
        public int Comp_MKey { get; set; }
        public string Type_Code { get; set; }
        public string Type_Desc { get; set; }
        public decimal Master_MKey { get; set; }
        public string? Module_Id { get; set; }
        public string? Delete_Flag { get; set; }
        public string? Add_TInfo1 { get; set; }
        public string? Add_TInfo2 { get; set; }
        public string? Add_TInfo3 { get; set; }
        public string? Add_IInfo1 { get; set; }
        public decimal? Add_IInfo2 { get; set; }
        public decimal? Add_IInfo3 { get; set; }
        public string Active_Key { get; set; }
        public decimal? User_ID { get; set; }
        public string? Type_Abbr { get; set; }
        public DateTime U_DateTime { get; set; }
        public string? Sub_Dept { get; set; }
        public decimal? Main_Dept { get; set; }
        public decimal? Country_Code { get; set; }
        public string? Navision_Link_ID { get; set; }
        public string? StpUserName { get; set; }
        public string? EDICode { get; set; }
        public string? MonthlyAllocationFlag { get; set; }
    }

    public class LocationDetails_Model
    {
        public string Type_Desc { get; set; }
        public int Bin_Mkey { get; set; }
        public string Location_Name { get; set; }
    }
    public class FileUploadModel
    {
        public IFormFile FileAttachment { get; set; }
        public string? FileName { get; set; }
        public string? Mkey { get; set; }
        public string? MODE { get; set; }
        public string? Entry_Sr_no { get; set; }
        public string? Action_by { get; set; }
        public string? Action { get; set; }
    }





    public class FileUpload_InvoiceNO_Model
    {
        public int Mkey { get; set;}
        public String? DOC_TYPE { get; set; }
        public String? DOC_Name { get; set; }
        public List<Dictionary<string, object>> FileContent { get; set; }
        public string? Upload_By { get; set; }   //Session_userId
        public string? Upload_Date { get; set; }   // Creation Date 
        public string? IS_MANDATORY { get; set;}
        public string? STATUS_FLAG { get; set; }
        public decimal? APPROVER_ID { get; set;}
        public DateTime? APPROVE_ACTION_DATE { get; set; }
       public string? ATTRIBUTE1  { get; set;}
       public string? ATTRIBUTE2 { get; set; }
       public string? ATTRIBUTE3 { get; set; }
       public string? ATTRIBUTE4 { get; set; }
       public string? ATTRIBUTE5 { get; set; }
       public decimal? CREATED_BY { get; set; }
       public DateTime? CREATION_DATE { get; set; }
       public decimal? LAST_UPDATED_BY { get; set; }
       public DateTime? LAST_UPDATE_DATE { get; set; }
       public string? DELETE_FLAG { get; set;}
    }

    public class Invoice_DOC_TRL_Model
    {
        public int Mkey { get; set; }
        public String? DOC_TYPE { get; set; }
        public String? DOC_Name { get; set; }
        public List<Dictionary<string, object>> FileContent { get; set; }
        public string? Upload_By { get; set; }   //Session_userId
        public string? Upload_Date { get; set; }   // Creation Date 
        public string? IS_MANDATORY { get; set; }
        public string? STATUS_FLAG { get; set; }
        public decimal? APPROVER_ID { get; set; }
        public DateTime? APPROVE_ACTION_DATE { get; set; }
        public string? ATTRIBUTE1 { get; set; }
        public string? ATTRIBUTE2 { get; set; }
        public string? ATTRIBUTE3 { get; set; }
        public string? ATTRIBUTE4 { get; set; }
        public string? ATTRIBUTE5 { get; set; }
        public decimal? CREATED_BY { get; set; }
        public DateTime? CREATION_DATE { get; set; }
        public decimal? LAST_UPDATED_BY { get; set; }
        public DateTime? LAST_UPDATE_DATE { get; set; }
        public string? DELETE_FLAG { get; set; }
    }

}
