using FMS_WebAPI.Repository.IRepositoryService;
using System.Data;
using System.Data.SqlClient;

namespace FMS_WebAPI.Repository.RepositoryService
{
    public class DapperDbConnection : IDapperDbConnection
    {
        public readonly string _connectionString;

        public DapperDbConnection(IConfiguration configuration)
        {
            _connectionString = configuration.GetConnectionString("DefaultConnection");
        }
        public IDbConnection CreateConnection()
        {
            return new SqlConnection(_connectionString);
        }
    }
}
