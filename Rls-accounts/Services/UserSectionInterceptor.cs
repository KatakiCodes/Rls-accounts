using Microsoft.EntityFrameworkCore.Diagnostics;
using System.Data.Common;
using System.Security.Claims;

namespace Rls_accounts.Services
{
    public class UserSectionInterceptor(IHttpContextAccessor httpContextAccessor) : DbConnectionInterceptor
    {
        public override async Task ConnectionOpenedAsync(DbConnection connection, ConnectionEndEventData eventData, CancellationToken cancellationToken = default)
        {
            var user = httpContextAccessor.HttpContext?.User;
            var userId = user?.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (!string.IsNullOrEmpty(userId) && !string.IsNullOrWhiteSpace(userId))
            {
                using (var command = connection.CreateCommand())
                {
                    command.CommandText = $"SET APP.CURRENT_USER_ID = '{userId}'";
                    await command.ExecuteNonQueryAsync(cancellationToken);
                }
            }
            await base.ConnectionOpenedAsync(connection, eventData, cancellationToken);
        }
    }
}
