using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;

namespace ApplicationSecurityICA2.Models
{
    public class ApplicationUser : IdentityUser
    {
        // Identity-related properties (PasswordHash, Email, etc.) are inherited.

        public DateTime? PasswordLastChanged { get; set; }
        // Allow null initially to avoid insert errors.
        public string? CurrentSessionToken { get; set; }

        // Extended membership properties.
        [Required(ErrorMessage = "First Name is required")]
        [StringLength(50, ErrorMessage = "First Name cannot exceed 50 characters")]
        public string FirstName { get; set; }

        [Required(ErrorMessage = "Last Name is required")]
        [StringLength(50, ErrorMessage = "Last Name cannot exceed 50 characters")]
        public string LastName { get; set; }

        [Required(ErrorMessage = "Gender is required")]
        public string Gender { get; set; }

        // NRIC will be encrypted before saving.
        [Required(ErrorMessage = "NRIC is required")]
        [StringLength(256)]
        public string NRIC { get; set; }

        [Required(ErrorMessage = "Date of Birth is required")]
        public DateTime DateOfBirth { get; set; }

        // For resume, only the file path is stored.
        public string? ResumePath { get; set; }

        [Required(ErrorMessage = "Who Am I is required")]
        [StringLength(500, ErrorMessage = "Description cannot exceed 500 characters")]
        public string WhoAmI { get; set; }

        // Registration-only fields (not stored in DB)
        [NotMapped]
        [DataType(DataType.Password)]
        [Required(ErrorMessage = "Password is required")]
        public string Password { get; set; }

        [NotMapped]
        [DataType(DataType.Password)]
        [Required(ErrorMessage = "Confirm Password is required")]
        [Compare("Password", ErrorMessage = "Passwords do not match")]
        public string ConfirmPassword { get; set; }

        // Resume file is used only for model binding.
        [NotMapped]
        public IFormFile ResumeFile { get; set; }
    }
}
