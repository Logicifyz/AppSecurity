using ApplicationSecurityICA2.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace ApplicationSecurityICA2.Services
{
    public class PasswordHistoryValidator : IPasswordValidator<ApplicationUser>
    {
        private readonly AuthDbContext _context;
        private readonly IPasswordHasher<ApplicationUser> _passwordHasher;
        private const int PasswordHistoryLimit = 2;

        public PasswordHistoryValidator(
            AuthDbContext context,
            IPasswordHasher<ApplicationUser> passwordHasher)
        {
            _context = context;
            _passwordHasher = passwordHasher;
        }

        public async Task<IdentityResult> ValidateAsync(
            UserManager<ApplicationUser> manager,
            ApplicationUser user,
            string password)
        {
            var previousPasswords = await _context.PasswordHistories
                .Where(ph => ph.UserId == user.Id)
                .OrderByDescending(ph => ph.CreatedAt)
                .Take(PasswordHistoryLimit)
                .ToListAsync();

            foreach (var pastPassword in previousPasswords)
            {
                if (_passwordHasher.VerifyHashedPassword(user, pastPassword.HashedPassword, password)
                    == PasswordVerificationResult.Success)
                {
                    return IdentityResult.Failed(new IdentityError
                    {
                        Description = "You cannot reuse one of your recent passwords."
                    });
                }
            }

            return IdentityResult.Success;
        }
    }
}