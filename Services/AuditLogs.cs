using ApplicationSecurityICA2.Models;
using System.Security.Claims;

namespace ApplicationSecurityICA2.Services
{
    public class AuditLogService
    {
        private readonly AuthDbContext _context;
        private readonly IHttpContextAccessor _httpContextAccessor;

        public AuditLogService(AuthDbContext context, IHttpContextAccessor httpContextAccessor)
        {
            _context = context;
            _httpContextAccessor = httpContextAccessor;
        }

        public async Task LogActionAsync(string action)
        {
            var userId = _httpContextAccessor.HttpContext.User.FindFirstValue(ClaimTypes.NameIdentifier);
            var auditLog = new AuditLog
            {
                UserId = userId,
                Action = action,
                Timestamp = DateTime.UtcNow
            };
            _context.AuditLogs.Add(auditLog);
            await _context.SaveChangesAsync();
        }
    }
}
