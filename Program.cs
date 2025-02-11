using Microsoft.AspNetCore.Identity;
using ApplicationSecurityICA2.Models;
using Microsoft.EntityFrameworkCore;
using ApplicationSecurityICA2.Services;
using Microsoft.AspNetCore.Identity.UI.Services;

var builder = WebApplication.CreateBuilder(args);

// Add configuration
builder.Services.AddSingleton<IConfiguration>(builder.Configuration);

// Add services to the container.
builder.Services.AddRazorPages();
builder.Services.AddDbContext<AuthDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("MyConnection"))
);

// Configure Identity
builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options =>
{
    // Password requirements
    options.Password.RequireDigit = true;
    options.Password.RequireLowercase = true;
    options.Password.RequireUppercase = true;
    options.Password.RequireNonAlphanumeric = true;
    options.Password.RequiredLength = 12;

    // Lockout settings
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(1);
    options.Lockout.MaxFailedAccessAttempts = 3;
    options.Lockout.AllowedForNewUsers = true;

    // User settings
    options.User.RequireUniqueEmail = true;
})
.AddEntityFrameworkStores<AuthDbContext>()
.AddSignInManager<SignInManager<ApplicationUser>>()
.AddPasswordValidator<PasswordHistoryValidator>()
.AddDefaultTokenProviders();

// Register the password hasher for ApplicationUser
builder.Services.AddSingleton<IPasswordHasher<ApplicationUser>, PasswordHasher<ApplicationUser>>();

builder.Services.AddHttpContextAccessor();

// Add session support
builder.Services.AddSession(options =>
{
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
    options.IdleTimeout = TimeSpan.FromMinutes(1); // Set session timeout
});

builder.Services.AddScoped<AuditLogService>();
builder.Services.AddTransient<IEmailSender, EmailSender>();

// Add logging
builder.Services.AddLogging(loggingBuilder =>
{
    loggingBuilder.AddConsole();
    loggingBuilder.SetMinimumLevel(LogLevel.Debug); // Set logging level to Debug for more detailed output
});

var app = builder.Build();

// Enable static files and session
app.UseStaticFiles();
app.UseSession();

app.UseRouting();

// Global error handling middleware: catch unhandled exceptions and status codes.
// You can choose to enable these in all environments for graceful error pages.
app.UseExceptionHandler("/Error"); // Handles unhandled exceptions by redirecting to /Error.
app.UseStatusCodePagesWithReExecute("/Error/{0}"); // Handles status codes (e.g., 404, 403) gracefully.

// Middleware to allow unauthenticated access to specific pages.
app.Use(async (context, next) =>
{
    var path = context.Request.Path;
    // Allow unauthenticated access to these pages:
    if (!path.StartsWithSegments("/Login") &&
        !path.StartsWithSegments("/Register") &&
        !path.StartsWithSegments("/ForgotPassword") &&
        !path.StartsWithSegments("/ResetPassword") &&
        !path.StartsWithSegments("/ForgotPasswordConfirmation") &&
        !path.StartsWithSegments("/ResetPasswordConfirmation") &&
        !path.StartsWithSegments("/TwoFactorLogin") &&  // Allow TwoFactorLogin
        !path.StartsWithSegments("/Error"))           // Allow Error page
    {
        if (context.Session.GetString("UserEmail") == null)
        {
            context.Response.Redirect("/Login");
            return;
        }
    }
    await next();
});

// Middleware to detect concurrent logins.
// If the session's token does not match the token in the user record, redirect to /Login.
app.Use(async (context, next) =>
{
    var sessionEmail = context.Session.GetString("UserEmail");
    if (!string.IsNullOrEmpty(sessionEmail))
    {
        var sessionToken = context.Session.GetString("UserSessionToken");
        var userManager = context.RequestServices.GetRequiredService<UserManager<ApplicationUser>>();
        var user = await userManager.FindByEmailAsync(sessionEmail);
        if (user != null)
        {
            // If the token in session doesn't match the token in the database, invalidate the session.
            if (user.CurrentSessionToken != sessionToken)
            {
                context.Session.Clear();
                context.Response.Redirect("/Login");
                return;
            }
        }
    }
    await next();
});

// Ensure that authentication and authorization middleware are registered.
app.UseAuthentication();
app.UseAuthorization();

app.MapRazorPages();

app.Run();
