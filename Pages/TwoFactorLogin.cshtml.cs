using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using ApplicationSecurityICA2.Models;
using Microsoft.Extensions.Logging;
using System.ComponentModel.DataAnnotations;
using System.Threading.Tasks;
using System;
using ApplicationSecurityICA2.Services;

namespace ApplicationSecurityICA2.Pages
{
    public class TwoFactorLoginModel : PageModel
    {
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly ILogger<TwoFactorLoginModel> _logger;
        private readonly AuditLogService _auditLogService;

        public TwoFactorLoginModel(AuditLogService auditLogService,
                                   SignInManager<ApplicationUser> signInManager,
                                   UserManager<ApplicationUser> userManager,
                                   ILogger<TwoFactorLoginModel> logger)
        {
            _signInManager = signInManager;
            _auditLogService = auditLogService;
            _userManager = userManager;
            _logger = logger;
        }

        [BindProperty]
        [Required(ErrorMessage = "Two-factor code is required.")]
        public string TwoFactorCode { get; set; }

        public string ErrorMessage { get; set; }

        public void OnGet() { }

        public async Task<IActionResult> OnPostAsync()
        {
            if (!TempData.ContainsKey("UserId"))
            {
                ErrorMessage = "Your session has expired. Please log in again.";
                return RedirectToPage("Login");
            }

            string userId = TempData["UserId"].ToString();
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                ErrorMessage = "Unable to load user.";
                return RedirectToPage("Login");
            }

            // Verify the two-factor token using the email provider.
            var isValid = await _userManager.VerifyTwoFactorTokenAsync(user, TokenOptions.DefaultEmailProvider, TwoFactorCode);
            if (isValid)
            {
                // If the user's email is not confirmed (e.g. during registration), mark it as confirmed.
                if (!user.EmailConfirmed)
                {
                    user.EmailConfirmed = true;
                    await _userManager.UpdateAsync(user);
                }

                // Generate a unique session token.
                var sessionToken = Guid.NewGuid().ToString();

                // Update the user record with the new session token.
                user.CurrentSessionToken = sessionToken;
                await _userManager.UpdateAsync(user);

                // Sign in the user.
                await _signInManager.SignInAsync(user, isPersistent: false);

                // Save the email and session token in session.
                HttpContext.Session.SetString("UserEmail", user.Email);
                HttpContext.Session.SetString("UserSessionToken", sessionToken);
                await _auditLogService.LogActionAsync("User logged in");
                _logger.LogInformation("User {Email} authenticated successfully via 2FA", user.Email);
                return RedirectToPage("/Home");
            }
            else
            {
                ErrorMessage = "Invalid two-factor code.";
                ModelState.AddModelError(string.Empty, "Invalid two-factor code.");
                return Page();
            }
        }
    }
}
