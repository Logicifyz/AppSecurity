using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.ComponentModel.DataAnnotations;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.WebUtilities;
using ApplicationSecurityICA2.Models;
using ApplicationSecurityICA2.Services;
using System;

namespace ApplicationSecurityICA2.Pages
{
    public class ResetPasswordModel : PageModel
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly AuditLogService _auditLogService;

        public ResetPasswordModel(AuditLogService auditLogService, UserManager<ApplicationUser> userManager)
        {
            _userManager = userManager;
            _auditLogService = auditLogService;
        }

        [BindProperty]
        public string Token { get; set; }

        [BindProperty]
        [EmailAddress]
        public string Email { get; set; }

        [BindProperty]
        [Required]
        [DataType(DataType.Password)]
        public string NewPassword { get; set; }

        [BindProperty]
        [Required]
        [DataType(DataType.Password)]
        [Compare("NewPassword", ErrorMessage = "Passwords do not match.")]
        public string ConfirmPassword { get; set; }

        // On GET, decode the token from the query string.
        public void OnGet(string token, string email)
        {
            Email = email;
            if (!string.IsNullOrEmpty(token))
            {
                var decodedBytes = WebEncoders.Base64UrlDecode(token);
                Token = Encoding.UTF8.GetString(decodedBytes);
            }
        }

        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid)
                return Page();

            var user = await _userManager.FindByEmailAsync(Email);
            if (user == null)
            {
                ModelState.AddModelError(string.Empty, "Invalid request.");
                return Page();
            }

            var result = await _userManager.ResetPasswordAsync(user, Token, NewPassword);
            if (result.Succeeded)
            {
                // Update the password change timestamp.
                user.PasswordLastChanged = DateTime.UtcNow;
                await _userManager.UpdateAsync(user);

                // Additional logic here (e.g., logging).
                return RedirectToPage("ResetPasswordConfirmation");
            }

            foreach (var error in result.Errors)
                ModelState.AddModelError(string.Empty, error.Description);

            return Page();
        }
    }
}
