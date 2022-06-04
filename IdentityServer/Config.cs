using System.Security.Claims;
using Duende.IdentityServer;
using Duende.IdentityServer.Models;

namespace IdentityServer;

public static class Config
{
    public static IEnumerable<IdentityResource> IdentityResources =>
        new IdentityResource[]
        {
            new IdentityResources.OpenId(),
            new IdentityResources.Profile(),
            new IdentityResource
            {
                Name = "role",
                UserClaims = new List<string> { "role" }
            }
        };

    public static IEnumerable<ApiScope> ApiScopes =>
        new ApiScope[]
        {
            new ApiScope(name: "api1.read", displayName: "api1 read access")
        };

    public static IEnumerable<ApiResource> ApiResources =>
        new[]
        {
            new ApiResource
            {
                Name = "api1",
                DisplayName = "Api 1 demo",
                Description = "Test of api resource",
                Scopes = new List<string> { "api1.read", "api1.write" },
                ApiSecrets = new List<Secret> { new Secret("ScopeSecret".Sha256()) },
                UserClaims = new List<string> { "role" }
            }
        };

    public static IEnumerable<Client> Clients =>
        new Client[]
        {
            new Client
            {
                ClientId = "client_id",
                // no interactive user, use the clientid/secret for authentication
                AllowedGrantTypes = GrantTypes.ClientCredentials,
                // secret for authentication
                ClientSecrets = { new Secret("secret".Sha256()) },
                Claims = new List<ClientClaim>
                {
                    new ClientClaim(ClaimTypes.GivenName, "John"),
                    new ClientClaim(ClaimTypes.Email, "john123@demoserver.com")
                },
                // scopes that client has access to
                AllowedScopes = { "api1.read" },
                Enabled = true
            },
            new Client
            {
                ClientId = "client_code",
                AllowedGrantTypes = GrantTypes.Code,
                // secret for authentication
                ClientSecrets = { new Secret("secret".Sha256()) },
                // scopes that client has access to
                AllowedScopes = { "openid", "api1.read" },
                RedirectUris = { "https://localhost:5001/identity/private/tokenfromcode" },
                RequirePkce = false,
                Enabled = true
            },
            new Client
            {
                ClientId = "client_pkce",
                AllowedGrantTypes = GrantTypes.Code,
                // secret for authentication
                ClientSecrets = { new Secret("secret".Sha256()) },
                // scopes that client has access to
                AllowedScopes = { "openid", "api1.read" },
                RedirectUris = { "https://localhost:5001/identity/private/tokenfromcodepkce" },
                RequirePkce = true,
                Enabled = true
            }
        };
}