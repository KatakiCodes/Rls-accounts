
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations;
using System.Security.Claims;
using Microsoft.OpenApi;
using Microsoft.IdentityModel.Tokens;
using Rls_accounts.Data;
using Rls_accounts.Contracts;
using Rls_accounts.Models;
using Rls_accounts.Services;

namespace Rls_accounts
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);



            var connectionString = builder.Configuration.GetConnectionString("DefaultConnection")
                ?? throw new InvalidOperationException("Configure ConnectionStrings:DefaultConnection.");
            var jwtKey = builder.Configuration["Jwt:SigningKey"]
                ?? throw new InvalidOperationException("Configure Jwt:SigningKey using a secret environment variable.");
            var jwtIssuer = builder.Configuration["Jwt:Issuer"]
                ?? throw new InvalidOperationException("Configure Jwt:Issuer.");
            var jwtAudience = builder.Configuration["Jwt:Audience"]
                ?? throw new InvalidOperationException("Configure Jwt:Audience.");

            if (Encoding.UTF8.GetByteCount(jwtKey) < 32)
            {
                throw new InvalidOperationException("Jwt:SigningKey must contain at least 32 bytes.");
            }


            builder.Services
                .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                .AddJwtBearer(options =>
                {
                    options.TokenValidationParameters = new TokenValidationParameters
                    {
                        ValidateIssuerSigningKey = true,
                        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey)),
                        ValidateIssuer = true,
                        ValidIssuer = jwtIssuer,
                        ValidateAudience = true,
                        ValidAudience = jwtAudience,
                        ValidateLifetime = true,
                        ClockSkew = TimeSpan.FromSeconds(30)
                    };
                });
            builder.Services.AddAuthorization();

            builder.Services.AddHttpContextAccessor();
            builder.Services.AddSingleton<UserSectionInterceptor>();


            builder.Services.AddDbContext<AppDbContext>((sp, options) =>
            {
                options.UseNpgsql(connectionString);
                options.AddInterceptors(sp.GetRequiredService<UserSectionInterceptor>());
            });
            builder.Services.AddScoped<IPasswordHasher<User>, PasswordHasher<User>>();
            builder.Services.AddSingleton<TokenService>();

            builder.Services.AddEndpointsApiExplorer();
            builder.Services.AddSwaggerGen(options =>
            {
                options.SwaggerDoc("v1", new OpenApiInfo
                {
                    Title = "Rls Accounts API",
                    Version = "v1"
                });
                options.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
                {
                    Name = "Authorization",
                    Type = SecuritySchemeType.Http,
                    Scheme = "bearer",
                    BearerFormat = "JWT",
                    In = ParameterLocation.Header,
                    Description = "Informe o token JWT emitido pelo endpoint de login."
                });
                options.AddSecurityRequirement(document => new OpenApiSecurityRequirement
                {
                    [new OpenApiSecuritySchemeReference("Bearer", document)] = []
                });
            });

            var app = builder.Build();

            // Configure the HTTP request pipeline.
            if (app.Environment.IsDevelopment())
            {
                app.UseSwagger();
                app.UseSwaggerUI();
            }

            app.UseHttpsRedirection();

            app.UseAuthentication();
            app.UseAuthorization();

            app.MapPost("/api/users", async (
                CreateUserRequest request,
                AppDbContext db,
                IPasswordHasher<User> passwordHasher,
                CancellationToken cancellationToken) =>
            {
                if (string.IsNullOrWhiteSpace(request.Email)
                    || !new EmailAddressAttribute().IsValid(request.Email)
                    || string.IsNullOrWhiteSpace(request.Password))
                {
                    return Results.BadRequest(new { message = "Email e senha válidos são obrigatórios." });
                }

                var email = request.Email.Trim().ToLowerInvariant();
                if (await db.Users.AnyAsync(user => user.Email == email, cancellationToken))
                {
                    return Results.Conflict(new { message = "Já existe um usuário com esse email." });
                }

                var user = new User { Email = email };
                user.PasswordHash = passwordHasher.HashPassword(user, request.Password);
                db.Users.Add(user);
                await db.SaveChangesAsync(cancellationToken);

                return Results.Created($"/api/users/{user.Id}", new UserResponse(user.Id, user.Email));
            })
            .AllowAnonymous()
            .WithName("CreateUser");

            app.MapPost("/api/auth/login", async (
                LoginRequest request,
                AppDbContext db,
                IPasswordHasher<User> passwordHasher,
                TokenService tokenService,
                CancellationToken cancellationToken) =>
            {
                if (string.IsNullOrWhiteSpace(request.Email) || string.IsNullOrEmpty(request.Password))
                {
                    return Results.Unauthorized();
                }

                var email = request.Email.Trim().ToLowerInvariant();
                var user = await db.Users.SingleOrDefaultAsync(
                    user => user.Email == email,
                    cancellationToken);

                if (user is null
                    || passwordHasher.VerifyHashedPassword(user, user.PasswordHash, request.Password)
                        == PasswordVerificationResult.Failed)
                {
                    return Results.Unauthorized();
                }

                return Results.Ok(new LoginResponse(tokenService.GenerateToken(user)));
            })
            .AllowAnonymous()
            .WithName("Login");

            app.MapGet("/api/accounts", async (AppDbContext db, CancellationToken cancellationToken) =>
            {
                var accounts = await db.Accounts
                    .AsNoTracking()
                    .Select(account => new AccountResponse(account.Id, account.Name))
                    .ToListAsync(cancellationToken);

                return Results.Ok(accounts);
            })
            .RequireAuthorization()
            .WithName("GetAccounts");

            app.MapPost("/api/accounts", async (
                CreateAccountRequest request,
                HttpContext httpContext,
                AppDbContext db,
                CancellationToken cancellationToken) =>
            {
                if (string.IsNullOrWhiteSpace(request.Name))
                {
                    return Results.BadRequest(new { message = "O nome da conta é obrigatório." });
                }

                var userIdValue = httpContext.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
                if (!int.TryParse(userIdValue, out var userId)
                    || !await db.Users.AnyAsync(user => user.Id == userId, cancellationToken))
                {
                    return Results.Unauthorized();
                }

                var account = new Account
                {
                    Name = request.Name.Trim(),
                    UserId = userId
                };

                db.Accounts.Add(account);
                await db.SaveChangesAsync(cancellationToken);

                return Results.Created(
                    $"/api/accounts/{account.Id}",
                    new AccountResponse(account.Id, account.Name));
            })
            .RequireAuthorization()
            .WithName("CreateAccount");

            app.Run();
        }
    }
}
