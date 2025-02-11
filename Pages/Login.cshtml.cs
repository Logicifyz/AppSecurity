using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Identity;
using ApplicationSecurityICA2.Models;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.Http;
using System.Threading.Tasks;
using System.Net.Http;
using System.Collections.Generic;
using Newtonsoft.Json;
using System;
using Microsoft.AspNetCore.Identity.UI.Services;
using ApplicationSecurityICA2.Services;
using Microsoft.AspNetCore.WebUtilities;
using System.Text;

namespace ApplicationSecurityICA2.Pages
{
    public class LoginModel : PageModel
    {
        private const string ReCaptchaSecretKey = "6Lekt84qAAAAAPVqnibvdims3jxIZrDmx4CnNK3b";
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly ILogger<LoginModel> _logger;
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly IEmailSender _emailSender;
        private readonly AuditLogService _auditLogService;

        public LoginModel(
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager,
            ILogger<LoginModel> logger,
            IHttpContextAccessor httpContextAccessor,
            IEmailSender emailSender,
            AuditLogService auditLogService)
        {
            _auditLogService = auditLogService;
            _userManager = userManager;
            _signInManager = signInManager;
            _logger = logger;
            _httpContextAccessor = httpContextAccessor;
            _emailSender = emailSender;
        }

        [BindProperty]
        public LoginViewModel Login { get; set; }
        public string ErrorMessage { get; set; }

        public IActionResult OnGet() => Page();

        public async Task<IActionResult> OnPostAsync()
        {
            // Retrieve the reCAPTCHA token from the form and remove it from model state.
            Login.Captcha = Request.Form["recaptchaToken"];
            ModelState.Remove("Login.Captcha");

            if (!ModelState.IsValid)
            {
                _logger.LogWarning("Invalid ModelState for login {Email}", Login.Email);
                return Page();
            }

            if (!await IsReCaptchaValidAsync(Login.Captcha))
            {
                ErrorMessage = "Invalid CAPTCHA. Please try again.";
                ModelState.AddModelError("Login.Captcha", "Captcha validation failed.");
                return Page();
            }

            var user = await _userManager.FindByEmailAsync(Login.Email);
            if (user == null)
            {
                ErrorMessage = "Invalid login credentials.";
                return Page();
            }

            // Enforce maximum password age: if expired, generate a reset token and redirect.
            var maxPasswordAge = TimeSpan.FromMinutes(3);
            if (DateTime.UtcNow - user.PasswordLastChanged > maxPasswordAge)
            {
                TempData["PasswordExpired"] = "Your password has expired. Please change your password to continue.";
                var resetToken = await _userManager.GeneratePasswordResetTokenAsync(user);
                var encodedToken = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(resetToken));
                return RedirectToPage("ResetPassword", new { email = user.Email, token = encodedToken });
            }

            if (user.TwoFactorEnabled)
            {
                // Use PasswordSignInAsync to check password and handle lockout.
                var result = await _signInManager.PasswordSignInAsync(
                    Login.Email,
                    Login.Password,
                    isPersistent: false,
                    lockoutOnFailure: true);

                if (result.IsLockedOut)
                {
                    ErrorMessage = "Your account has been locked out.";
                    return Page();
                }

                // If two-factor is required (as expected when 2FA is enabled), proceed with token generation.
                if (result.RequiresTwoFactor)
                {
                    var token = await _userManager.GenerateTwoFactorTokenAsync(user, TokenOptions.DefaultEmailProvider);
                    await _emailSender.SendEmailAsync(user.Email, "Your 2FA Code", $"Your code is: {token}");

                    TempData["UserId"] = user.Id;
                    TempData["RememberMe"] = false;
                    return RedirectToPage("TwoFactorLogin");
                }

                if (!result.Succeeded)
                {
                    ErrorMessage = "Invalid login credentials.";
                    return Page();
                }
            }
            else
            {
                // Standard sign-in process for users without 2FA.
                var result = await _signInManager.PasswordSignInAsync(Login.Email, Login.Password, false, lockoutOnFailure: true);

                if (result.IsLockedOut)
                {
                    ErrorMessage = "Your account has been locked out.";
                    return Page();
                }
                if (!result.Succeeded)
                {
                    ErrorMessage = "Invalid login credentials.";
                    return Page();
                }

                // Set session values.
                HttpContext.Session.SetString("UserEmail", user.Email);
                HttpContext.Session.SetString("UserSessionToken", user.CurrentSessionToken ?? string.Empty);

                return RedirectToPage("/Home");
            }

            // Fallback in case no branch is hit.
            ErrorMessage = "Invalid login attempt.";
            return Page();
        }


        private async Task<bool> IsReCaptchaValidAsync(string token)
        {
            using var client = new HttpClient();
            var content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                { "secret", ReCaptchaSecretKey },
                { "response", token }
            });
            var response = await client.PostAsync("https://www.google.com/recaptcha/api/siteverify", content);
            var json = await response.Content.ReadAsStringAsync();
            dynamic result = JsonConvert.DeserializeObject(json);
            return result.success == true && result.score >= 0.5;
        }

        public async Task<IActionResult> OnPostLogoutAsync()
        {
            await _signInManager.SignOutAsync();
            await _auditLogService.LogActionAsync("User logged out");
            _httpContextAccessor.HttpContext.Session.Clear();
            return RedirectToPage("/Login");
        }
    }
}
