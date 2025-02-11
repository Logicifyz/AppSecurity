using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace ApplicationSecurityICA2.Models
{
    public class AuthDbContext : IdentityDbContext<ApplicationUser>
    {
        public AuthDbContext(DbContextOptions<AuthDbContext> options)
    : base(options)
        {
            try
            {
                Console.WriteLine($"Using database: {Database.GetDbConnection().ConnectionString}");
                Database.OpenConnection();
                Console.WriteLine("Database connection successful.");
                Database.CloseConnection();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Database connection failed: {ex.Message}");
            }
        }
  
        public DbSet<AuditLog> AuditLogs { get; set; }   
        public DbSet<PasswordHistory> PasswordHistories { get; set; }

 


    protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

        }
    }
}
