using System;
using System.ComponentModel.DataAnnotations;

namespace ApplicationSecurityICA2.Models
{
    public class PasswordHistory
    {
        public int Id { get; set; }
        public string UserId { get; set; }
        public string HashedPassword { get; set; }
        public DateTime CreatedAt { get; set; }
    }

}
