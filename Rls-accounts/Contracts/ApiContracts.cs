namespace Rls_accounts.Contracts;

public sealed record CreateUserRequest(string? Email, string? Password);
public sealed record CreateAccountRequest(string? Name);
public sealed record LoginRequest(string? Email, string? Password);
public sealed record UserResponse(int Id, string Email);
public sealed record LoginResponse(string AccessToken);
public sealed record AccountResponse(int Id, string Name);
