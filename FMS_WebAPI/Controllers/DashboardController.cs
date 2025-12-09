using Dapper;
using FMS_WebAPI.Model;
using FMS_WebAPI.Repository.IRepositoryService;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Data;
using System.Data.Common;
using System.Data.SqlClient;
using System.Net;
using System.Reflection;

namespace FMS_WebAPI.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    [Authorize]
    public class DashboardController : ControllerBase
    {
        private readonly IAuthService _authService;
        private readonly IConfiguration _configuration;
        private readonly IDapperDbConnection _dbConnection;

        public DashboardController(IAuthService authService, SqlConnection sqlConnection, IConfiguration configuration, IDapperDbConnection connection)
        {
            _authService = authService;
            _configuration = configuration;
            _dbConnection = connection;

        }

         [HttpGet("GetUploads_NT")]
         public async Task<IActionResult> GetUploads()
            {
                var responseObject = new ResponseObject<object>();
                try
                {
                    int parameter1 = 0;
                    int parameter2 = 0;
                    int parameter3 = 0;
                    int parameter4 = 0;
                    string parameter5 = null;
                    string parameter6 = null;
                    string parameter7 = null;
                    string parameter8 = null;
                    using var connection = _dbConnection.CreateConnection();
                    // Setup Dapper parameters
                    var parameters = new DynamicParameters();
                    parameters.Add("@Parameter1", parameter1, DbType.Int32);
                    parameters.Add("@Parameter2", parameter2, DbType.Int32);
                    parameters.Add("@Parameter3", parameter3, DbType.Int32);
                    parameters.Add("@Parameter4", parameter4, DbType.Int32);
                    parameters.Add("@Parameter5", parameter5, DbType.String);
                    parameters.Add("@Parameter6", parameter6, DbType.String);
                    parameters.Add("@Parameter7", parameter7, DbType.String);
                    parameters.Add("@Parameter8", parameter8, DbType.String);
                    // Execute stored procedure and map to Invoice model
                    var invoices = await connection.QueryAsync<Invoice_Model>("SP_GET_INVOICE_DEATAILS",parameters,commandType: CommandType.StoredProcedure);
                    if (invoices.Any())
                    {
                        responseObject.Status = "Success";
                        responseObject.Message = "Invoice Details Fetch Successfully";
                        responseObject.Data = invoices;
                    }
                    else
                    {
                        responseObject.Status = "Success";
                        responseObject.Message = "No Data Available";
                        responseObject.Data = invoices;
                    }
                        return Ok(responseObject);
                }
                catch (Exception ex)
                {
                    responseObject.Status = "Error";
                    responseObject.Message = $"Error retrieving invoices: {ex.Message}";
                    responseObject.Data = null;
                    return Ok(responseObject);
                }
            }

        [HttpGet("GetUploadFileRec-By_Mkey_NT")]
        public async Task<IActionResult> GetUploadFileRec(string mkey ,int? Session_userId ,int?Business_GroupId)
        {
            var responseObject = new ResponseObject<object>();
            try
            {
                using var connection = _dbConnection.CreateConnection();
                var parameters = new DynamicParameters();
                parameters.Add("@Parameter1", mkey, DbType.Decimal);
                parameters.Add("@Parameter2", 0, DbType.Decimal); // optional
                parameters.Add("@Session_userId", Session_userId, DbType.Int32); // optional
                parameters.Add("@Business_GroupId", Business_GroupId, DbType.Int32); // optional
                // Execute stored procedure and map results
                var documents = await connection.QueryAsync<InvoiceDocumentModel>("SP_GET_INVOICE_DOC_DEATAILS",parameters,commandType: CommandType.StoredProcedure);
                if (documents.Any())
                {
                    responseObject.Status = "Success";
                    responseObject.Message = "INVOICE_DOC_DEATAILS Fetch Successfully";
                    responseObject.Data = documents;
                    return Ok(responseObject);
                }
                else
                {
                    responseObject.Status = "Success";
                    responseObject.Message = "No Data Available";
                    responseObject.Data = documents.ToList();
                    return Ok(responseObject);
                }
            }
            catch(Exception ex)
            {
                responseObject.Status = "Error";
                responseObject.Message = $"Error retrieving invoices: {ex.Message}";
                responseObject.Data = null;
                return Ok(responseObject);
            }
        }

        [HttpPost("ReadFileUploaded_NT")]
        public async Task<IActionResult> ReadFileUploaded([FromBody] ReadFileUpload_Model upload_Model)
        {
            var responseObject = new ResponseObject<object>();

            try
            {
                using var connection = _dbConnection.CreateConnection();
                await ((SqlConnection)connection).OpenAsync();

                string query = @"SELECT mkey AS MKEY,FileContents, FILE_NAME FROM INVOICE_DOC_TRL WHERE mkey = @Identifier AND SR_NO = @SrNo";
                using var command = new SqlCommand(query, (SqlConnection)connection);
                command.Parameters.AddWithValue("@Identifier", upload_Model.Identifier);
                command.Parameters.AddWithValue("@SrNo", upload_Model.SrNo);
                using var reader = await command.ExecuteReaderAsync();
                if (!await reader.ReadAsync())
                {
                    responseObject.Status = "Failed";
                    responseObject.Message = "No file found.";
                    return NotFound(responseObject);
                }

                // Read data
                byte[] fileBytes = (byte[])reader["FileContents"];
                string fileName = reader["FILE_NAME"].ToString();

                // Convert bytes to Base64 string
                string base64 = Convert.ToBase64String(fileBytes);

                // Bind into Model
                var fileModel = new FileUploadResultModel
                {
                    MKey = (int)reader["MKEY"],
                    FileName = fileName,
                    Base64File = base64,
                    ContentType = "application/pdf"
                };

                // Return as JSON
                responseObject.Status = "Success";
                responseObject.Message = "File retrieved successfully";
                responseObject.Data = fileModel;

                return Ok(responseObject);
            }
            catch (Exception ex)
            {
                responseObject.Status = "Error";
                responseObject.Message = $"Error: {ex.Message}";
                responseObject.Data = null;
                return StatusCode(500, responseObject);
            }
        }

        [HttpPost("Dashboard-insertUploadFile")]
        public async Task<IActionResult> InsertUploadFile([FromBody] FileUploadModel fileUpload)
        {
            var responseObject = new ResponseObject<object>();
            if (fileUpload.FileAttachment == null || fileUpload.FileAttachment.Length == 0) 
            { 
                return BadRequest(new { status = "error", message = "File not provided" }); 
            }
            byte[] fileBytes; 
            using (var ms = new MemoryStream()) 
            { 
                await fileUpload.FileAttachment.CopyToAsync(ms); fileBytes = ms.ToArray(); 
            }
            try
            {
                using var connection = _dbConnection.CreateConnection();
                await ((SqlConnection)connection).OpenAsync(); 
                string statement;
                var userName = User.Identity.Name;
                int UserId= await _authService.GetUserIdbyUserName(userName);
                // Convert Base64 string back to byte array
                //byte[] fileBytes = Convert.FromBase64String(fileUpload.Base64File);
                if (fileUpload.MODE == "M") 
                {
                    statement = @"UPDATE INVOICE_DOC_TRL SET FILECONTENTS = @FileContents, FILE_NAME = @FileName, UPLOADED_BY = @Action_by, UPLOAD_DATE = GETDATE(), STATUS_FLAG = @Action, LAST_UPDATED_BY = @Action_by, LAST_UPDATE_DATE = GETDATE() WHERE MKEY = @Mkey AND SR_NO = @Entry_Sr_no;"; 
                } 
                else 
                { 
                    statement = @"INSERT INTO INVOICE_DOC_TRL (FileContents, FileName, UPLOADED_BY, UPLOAD_DATE, STATUS_FLAG) VALUES (@FileContents, @FileName, @Action_by, GETDATE(), @Action); SELECT CAST(SCOPE_IDENTITY() AS int);"; 
                }

                var parameters = new DynamicParameters(); 
                parameters.Add("@FileContents", fileBytes, DbType.Binary); 
                parameters.Add("@FileName", fileUpload.FileName); 
                parameters.Add("@Mkey", fileUpload.Mkey); 
                parameters.Add("@Entry_Sr_no", fileUpload.Entry_Sr_no); 
                parameters.Add("@Action_by", string.IsNullOrEmpty(fileUpload.Action_by) ? UserId : fileUpload.Action_by); 
                parameters.Add("@Action", fileUpload.Action);

                int newId = 0; 
                if (fileUpload.MODE == "M") 
                { 
                    await connection.ExecuteAsync(statement, parameters); 
                } 
                else 
                {
                    newId = await connection.ExecuteScalarAsync<int>(statement, parameters); 
                }

                // Update header status
                string headerUpdate = @"UPDATE INVOICE_hdr SET status_flag = @Action WHERE mkey = @Mkey"; 
                await connection.ExecuteAsync(headerUpdate, new { Action = fileUpload.Action, Mkey = fileUpload.Mkey });
                responseObject.Status = "Success";
                responseObject.Message = "File uploaded successfully";
                responseObject.Data = new { Mkey = newId, FileName = fileUpload.FileName, };
                return Ok(responseObject);
                //return Ok(new { status = "success", message = "File uploaded successfully", Data =  new {Mkey= newId ,FileName= fileUpload.FileName , } });
            }
            catch (Exception ex)
            {
                responseObject.Status = "Error";
                responseObject.Message = $"Error uploading file: {ex.Message}";
                responseObject.Data = null;
                return StatusCode(500, responseObject);
            }
        }
    }
}
