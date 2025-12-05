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
}
