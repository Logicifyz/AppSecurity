using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;
using ApplicationSecurityICA2.Models;
using ApplicationSecurityICA2.Services;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.Identity.UI.Services;

namespace ApplicationSecurityICA2.Pages
{
    public class RegisterModel : PageModel
    {
        private readonly AuthDbContext _context;
        private readonly IWebHostEnvironment _env;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly byte[] _encryptionKey;
        private readonly ILogger<RegisterModel> _logger;
        private readonly IEmailSender _emailSender;

        public RegisterModel(
            AuthDbContext context,
            IWebHostEnvironment env,
            IConfiguration config,
            ILogger<RegisterModel> logger,
            UserManager<ApplicationUser> userManager,
            IEmailSender emailSender)
        {
            _context = context;
            _env = env;
            _logger = logger;
            _userManager = userManager;
            _emailSender = emailSender;

            // Get and validate encryption key.
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

        // Bind directly to ApplicationUser for registration.
        [BindProperty]
        public ApplicationUser InputUser { get; set; } = new ApplicationUser();

        [TempData]
        public string SuccessMessage { get; set; }

        public void OnGet()
        {
            // Display the registration form.
        }

        public async Task<IActionResult> OnPostAsync()
        {
            _logger.LogInformation("Registration attempt for {Email}", InputUser.Email);
            if (!ModelState.IsValid)
            {
                return Page();
            }

            // Check if email already exists.
            var existingUser = await _userManager.FindByEmailAsync(InputUser.Email);
            if (existingUser != null)
            {
                _logger.LogWarning("Duplicate user for email: {Email}", InputUser.Email);
                ModelState.AddModelError(string.Empty, "Email address is already registered");
                return Page();
            }

            // Validate and save resume file.
            var resumeFile = InputUser.ResumeFile;
            var (fileValid, validationError) = ValidateResumeFile(resumeFile);
            if (!fileValid)
            {
                ModelState.AddModelError("InputUser.ResumeFile", validationError);
                return Page();
            }
            var (filePath, resumeError) = await SaveResumeFile(resumeFile);
            if (!string.IsNullOrEmpty(resumeError))
            {
                ModelState.AddModelError("InputUser.ResumeFile", resumeError);
                return Page();
            }
            InputUser.ResumePath = filePath;

            // Encrypt NRIC before storing.
            try
            {
                InputUser.NRIC = EncryptString(InputUser.NRIC);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "NRIC encryption failed");
                ModelState.AddModelError("InputUser.NRIC", "Error processing NRIC");
                return Page();
            }
            InputUser.UserName = InputUser.Email;
            // Create the user via UserManager. This will hash the password and store it in PasswordHash.
            var result = await _userManager.CreateAsync(InputUser, InputUser.Password);
            if (!result.Succeeded)
            {
                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError(string.Empty, error.Description);
                }
                return Page();
            }

            // Optionally generate 2FA token and send email.
            var token = await _userManager.GenerateTwoFactorTokenAsync(InputUser, TokenOptions.DefaultEmailProvider);
            await _emailSender.SendEmailAsync(InputUser.Email, "Email Confirmation Code", $"Your confirmation code is: {token}");

            TempData["UserId"] = InputUser.Id;
            TempData["RememberMe"] = "false";
            SuccessMessage = "Registration successful! Please confirm your email.";

            return RedirectToPage("TwoFactorLogin");
        }

        private (bool isValid, string error) ValidateResumeFile(Microsoft.AspNetCore.Http.IFormFile file)
        {
            if (file == null || file.Length == 0)
                return (false, "Resume file is required");

            if (file.Length > 5 * 1024 * 1024) // 5MB limit
                return (false, "File size must be less than 5MB");

            var allowedExtensions = new[] { ".pdf", ".docx" };
            var allowedMimeTypes = new[] {
                "application/pdf",
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
            };

            var extension = Path.GetExtension(file.FileName).ToLower();
            if (!allowedExtensions.Contains(extension) || !allowedMimeTypes.Contains(file.ContentType))
                return (false, "Only PDF and DOCX files allowed");

            return (true, null);
        }

        private async Task<(string path, string error)> SaveResumeFile(Microsoft.AspNetCore.Http.IFormFile file)
        {
            try
            {
                var uploadsDir = Path.Combine(_env.WebRootPath, "uploads");
                if (!Directory.Exists(uploadsDir))
                {
                    Directory.CreateDirectory(uploadsDir);
                }
                var fileName = $"{Guid.NewGuid()}{Path.GetExtension(file.FileName)}";
                var fullPath = Path.Combine(uploadsDir, fileName);
                using (var stream = new FileStream(fullPath, FileMode.Create))
                {
                    await file.CopyToAsync(stream);
                }
                return ($"/uploads/{fileName}", null);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Resume file save failed");
                return (null, "Error saving resume file");
            }
        }

        private string EncryptString(string plainText)
        {
            if (string.IsNullOrWhiteSpace(plainText))
            {
                throw new ArgumentException("NRIC cannot be empty");
            }
            using var aes = Aes.Create();
            aes.Key = _encryptionKey;
            aes.GenerateIV();
            using var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
            using var ms = new MemoryStream();
            ms.Write(aes.IV, 0, aes.IV.Length);
            using (var cryptoStream = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
            using (var sw = new StreamWriter(cryptoStream))
            {
                sw.Write(plainText);
            }
            return Convert.ToBase64String(ms.ToArray());
        }
    }
}
