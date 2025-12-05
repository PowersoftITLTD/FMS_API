using System.ComponentModel.DataAnnotations;

namespace FMS_WebAPI.Model
{
    public class Invoice_Model
    {
        public decimal MKEY { get; set; }                     // NOT NULL
        public string INVOICE_NO { get; set; }               // NOT NULL
        public DateTime INVOICE_DATE { get; set; }           // NOT NULL
        public string? CUSTOMER_NAME { get; set; }            // NOT NULL
        public string? CAREGORY { get; set; }                // NOT NULL
        public decimal? WAREHOUSE_ID { get; set; }           // NULL
        public string? WAREHOUSE_CODE { get; set; }           // NULL
        public string? STATUS_FLAG { get; set; }              // NULL
        public decimal? APPROVER_ID { get; set; }            // NULL
        public DateTime? APPROVE_ACTION_DATE { get; set; }   // NULL
        public string? ATTRIBUTE1 { get; set; }               // NULL
        public string? ATTRIBUTE2 { get; set; }               // NULL
        public string? ATTRIBUTE3 { get; set; }               // NULL
        public string? ATTRIBUTE4 { get; set; }               // NULL
        public string?  ATTRIBUTE5 { get; set; }               // NULL
        public decimal?  CREATED_BY { get; set; }              // NOT NULL
        public DateTime CREATION_DATE { get; set; }          // NOT NULL
        public decimal? LAST_UPDATED_BY { get; set; }        // NULL
        public DateTime? LAST_UPDATE_DATE { get; set; }      // NULL
        public string DELETE_FLAG { get; set; }
    }

    public class InvoiceDocumentModel
    {
        public decimal MKEY { get; set; }
        public decimal SR_NO { get; set; }
        public string? DOC_NAME { get; set; }
        public string? DOC_TYPE { get; set; }
        public string? FILE_NAME { get; set; }
        public byte[]? FILECONTENTS { get; set; }
        public string? UPLOADED_BY { get; set; }
        public DateTime? UPLOAD_DATE { get; set; }
        public string? IS_MANDATORY { get; set; }
        public string? STATUS_FLAG { get; set; }
        public string? STATUS { get; set; }
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
        public string? DELETE_FLAG { get; set; }
    }

    public class EncryptedDataRequest
    {
        [Required]
        public string FileName { get; set; }

        // Multiple ways to send encrypted data

        // Option 1: As byte array (for JSON)
        public byte[] EncryptedBytes { get; set; }

        // Option 2: As Base64 string
        public string EncryptedDataBase64 { get; set; }

        // Option 3: As hex string
        public string EncryptedDataHex { get; set; }

        // Option 4: Generic string (will try to detect format)
        public string EncryptedDataString { get; set; }
    }

    public class EncryptedFileDto
    {
        public string FileName { get; set; }
        public string EncryptedData { get; set; }
    }

    public class EncryptedLogin_Model
    {
        public string loginCredential { get; set; }
    }
}
