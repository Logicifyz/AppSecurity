using System.ComponentModel.DataAnnotations;

namespace ApplicationSecurityICA2.Models
{
    public class LoginViewModel
    {
        [Required(ErrorMessage = "Email is required")]
        [EmailAddress(ErrorMessage = "Invalid Email format")]
        public string Email { get; set; }

        [Required(ErrorMessage = "Password is required")]
        [DataType(DataType.Password)]
        public string Password { get; set; }

        // This property will be populated manually with the token from the form.
        public string Captcha { get; set; }
    }
}
