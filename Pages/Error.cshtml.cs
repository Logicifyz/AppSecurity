using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace ApplicationSecurityICA2.Pages
{
    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public class ErrorModel : PageModel
    {
        public int? StatusCode { get; set; }
        public string ErrorMessage { get; set; }

        // The status code is provided as a route parameter, if any.
        public void OnGet(int? code)
        {
            StatusCode = code ?? 500;
            switch (StatusCode)
            {
                case 404:
                    ErrorMessage = "Sorry, the page you requested could not be found.";
                    break;
                case 403:
                    ErrorMessage = "Sorry, you are not authorized to access this page.";
                    break;
                case 500:
                    ErrorMessage = "An unexpected error occurred. Please try again later.";
                    break;
                default:
                    ErrorMessage = "An error occurred. Please try again.";
                    break;
            }
        }
    }
}
