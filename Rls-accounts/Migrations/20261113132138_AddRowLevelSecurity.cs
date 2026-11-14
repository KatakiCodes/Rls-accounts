using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Rls_accounts.Migrations
{
    /// <inheritdoc />
    public partial class AddRowLevelSecurity : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {

            // 1. Ativar e forçar Row Level Security (evita bypass de donos de tabela)
            migrationBuilder.Sql(@"
                ALTER TABLE public.""Accounts"" ENABLE ROW LEVEL SECURITY;
                ALTER TABLE public.""Accounts"" FORCE ROW LEVEL SECURITY;
            ");

            // 2. Políticas RLS associadas diretamente à role de DML
            // O uso de NULLIF evita quebra caso app.current_user_id esteja vazio ou indefinido
            migrationBuilder.Sql(@"
                CREATE POLICY rls_user_self_only ON public.""Accounts""
                    FOR ALL
                    TO app_rls_role
                    USING (""UserId"" = NULLIF(current_setting('app.current_user_id', true), '')::int)
                    WITH CHECK (""UserId"" = NULLIF(current_setting('app.current_user_id', true), '')::int);
            ");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            // 1. Remover políticas RLS
            migrationBuilder.Sql(@"
                DROP POLICY IF EXISTS rls_user_self_only ON public.""Accounts"";
            ");

            // 2. Desativar RLS e o modo FORCE
            migrationBuilder.Sql(@"
                ALTER TABLE public.""Accounts"" NO FORCE ROW LEVEL SECURITY;
                ALTER TABLE public.""Accounts"" DISABLE ROW LEVEL SECURITY;
            ");

            
        }
    }
}
