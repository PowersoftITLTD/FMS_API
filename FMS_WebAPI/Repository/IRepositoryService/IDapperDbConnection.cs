using System.Data;

namespace FMS_WebAPI.Repository.IRepositoryService
{
    public interface IDapperDbConnection
    {
        public IDbConnection CreateConnection();
    }
}
