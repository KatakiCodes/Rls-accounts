namespace Rls_accounts.Models
{
    public class User
    {
        public int Id { get; set; }
        public string Email { get; set; } = string.Empty;
        public string PasswordHash { get; set; } = string.Empty;
        public List<Account> Accounts { get; set; } = [];
    }
}
