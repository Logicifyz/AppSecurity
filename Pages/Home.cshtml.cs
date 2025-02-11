using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Identity;
using ApplicationSecurityICA2.Models;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using ApplicationSecurityICA2.Services;
using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;

namespace ApplicationSecurityICA2.Pages
{
    public class HomeModel : PageModel
    {
        private readonly ILogger<HomeModel> _logger;
        private readonly byte[] _encryptionKey;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly AuditLogService _auditLogService;

        // Change property type to ApplicationUser.
        public ApplicationUser LoggedInUser { get; set; }

        public HomeModel(AuditLogService auditLogService, IConfiguration config, ILogger<HomeModel> logger, UserManager<ApplicationUser> userManager)
        {
            _logger = logger;
            _userManager = userManager;
            _auditLogService = auditLogService;
            var base64Key = config["EncryptionKey"];
            try
            {
                _encryptionKey = Convert.FromBase64String(base64Key);
                if (_encryptionKey.Length != 32)
                {
                    _logger.LogError("Invalid encryption key length: {Length} bytes", _encryptionKey.Length);
                    throw new ArgumentException("Invalid 256-bit encryption key");
                }
            }
            catch (Exception ex)
            {
                _logger.LogCritical(ex, "Encryption key configuration error");
                throw;
            }
        }

        public async Task<IActionResult> OnGetAsync()
        {
            var userEmail = HttpContext.Session.GetString("UserEmail");
            if (string.IsNullOrEmpty(userEmail))
            {
                return RedirectToPage("/Login");
            }
            LoggedInUser = await _userManager.FindByEmailAsync(userEmail);
            if (LoggedInUser != null)
            {
                try
                {
                    // Decrypt NRIC before displaying.
                    LoggedInUser.NRIC = DecryptString(LoggedInUser.NRIC);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error processing user {Email}", LoggedInUser.Email);
                    LoggedInUser.NRIC = "Decryption error";
                }
            }
            return Page();
        }

        private string DecryptString(string cipherText)
        {
            if (string.IsNullOrWhiteSpace(cipherText))
                return string.Empty;
            byte[] fullCipher = Convert.FromBase64String(cipherText);
            byte[] iv = fullCipher.Take(16).ToArray();
            byte[] cipher = fullCipher.Skip(16).ToArray();
            using var aes = Aes.Create();
            aes.Key = _encryptionKey;
            aes.IV = iv;
            using var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
            using var ms = new MemoryStream(cipher);
            using var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read);
            using var sr = new StreamReader(cs);
            return sr.ReadToEnd();
        }

        public async Task<IActionResult> OnPostLogoutAsync()
        {
            HttpContext.Session.Clear();
            await _auditLogService.LogActionAsync("User logged out");
            return RedirectToPage("/Login");
        }
        public async Task<IActionResult> OnPostToggleTwoFactorAsync()
        {
            var userEmail = HttpContext.Session.GetString("UserEmail");
            if (string.IsNullOrEmpty(userEmail))
            {
                return RedirectToPage("/Login");
            }

            var user = await _userManager.FindByEmailAsync(userEmail);
            if (user == null)
            {
                return RedirectToPage("/Login");
            }

            // Toggle the TwoFactorEnabled property.
            user.TwoFactorEnabled = !user.TwoFactorEnabled;

            // Update the user in the database.
            var result = await _userManager.UpdateAsync(user);
            if (!result.Succeeded)
            {
                _logger.LogError("Failed to update 2FA setting for user {Email}. Errors: {Errors}",
                    user.Email,
                    string.Join(", ", result.Errors.Select(e => e.Description)));
                // Optionally add a user-facing error message.
            }
            else
            {
                await _auditLogService.LogActionAsync($"User toggled 2FA to {(user.TwoFactorEnabled ? "ON" : "OFF")}");
            }

            // Refresh the LoggedInUser property so the toggle reflects the new setting.
            LoggedInUser = user;
            return RedirectToPage();
        }

    }
}
