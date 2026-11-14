using Microsoft.EntityFrameworkCore;
using Rls_accounts.Models;

namespace Rls_accounts.Data;

public class AppDbContext: DbContext
{
    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options)
    { }
    public DbSet<User> Users { set; get; }
    public DbSet<Account> Accounts { set; get; }
}
