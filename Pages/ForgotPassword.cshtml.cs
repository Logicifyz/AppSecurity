using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using System.ComponentModel.DataAnnotations;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.WebUtilities;
using ApplicationSecurityICA2.Models;
using System;

namespace ApplicationSecurityICA2.Pages
{
    public class ForgotPasswordModel : PageModel
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IEmailSender _emailSender;

        public ForgotPasswordModel(UserManager<ApplicationUser> userManager, IEmailSender emailSender)
        {
            _userManager = userManager;
            _emailSender = emailSender;
        }

        [BindProperty]
        [Required]
        [EmailAddress]
        public string Email { get; set; }

        public void OnGet() { }

        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid)
                return Page();

            var user = await _userManager.FindByEmailAsync(Email);
            if (user == null)
            {
                ModelState.AddModelError(string.Empty, "Email not found.");
                return Page();
            }

            // Enforce minimum password age: block reset if password was changed less than 3 minutes ago.
            var minPasswordAge = TimeSpan.FromMinutes(3);
            var passwordAge = DateTime.UtcNow - user.PasswordLastChanged;
            if (passwordAge < minPasswordAge)
            {
                ModelState.AddModelError(string.Empty, "Your password was recently changed. Please wait a few minutes before requesting a reset.");
                return Page();
            }

            // Generate the reset token and encode it for safe URL usage.
            var token = await _userManager.GeneratePasswordResetTokenAsync(user);
            var encodedToken = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token));

            // Generate the reset URL. (Ensure you have a ResetPassword page set up)
            var resetUrl = Url.Page(
                "/ResetPassword",
                null,
                new { email = Email, token = encodedToken },
                Request.Scheme);

            await _emailSender.SendEmailAsync(Email, "Password Reset",
                $"Click <a href='{resetUrl}'>here</a> to reset your password.");

            return RedirectToPage("ForgotPasswordConfirmation");
        }
    }
}
