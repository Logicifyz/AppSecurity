using MailKit.Net.Smtp;
using MailKit.Security;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.Extensions.Configuration;
using MimeKit;
using System.Threading.Tasks;

namespace ApplicationSecurityICA2.Services
{
    public class EmailSender : IEmailSender
    {
        private readonly IConfiguration _configuration;

        public EmailSender(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        public async Task SendEmailAsync(string email, string subject, string htmlMessage)
        {
            var emailSettings = _configuration.GetSection("EmailSettings");
            var host = emailSettings["Host"];
            var port = int.Parse(emailSettings["Port"]);
            var user = emailSettings["User"];
            var pass = emailSettings["Password"];
            var enableSSL = bool.Parse(emailSettings["EnableSSL"] ?? "true");

            var message = new MimeMessage();
            message.From.Add(new MailboxAddress("AppSecurity", user));
            message.To.Add(new MailboxAddress("", email));
            message.Subject = subject;

            var bodyBuilder = new BodyBuilder { HtmlBody = htmlMessage };
            message.Body = bodyBuilder.ToMessageBody();

            using (var client = new SmtpClient())
            {
                // For Gmail on port 465, use SslOnConnect.
                await client.ConnectAsync(host, port, enableSSL ? SecureSocketOptions.SslOnConnect : SecureSocketOptions.None);
                await client.AuthenticateAsync(user, pass);
                await client.SendAsync(message);
                await client.DisconnectAsync(true);
            }
        }
    }
}
