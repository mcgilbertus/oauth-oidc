using System.Security.Cryptography;
using System.Text;
using IdentityModel;
using IdentityModel.Client;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Swashbuckle.AspNetCore.Annotations;
using WebApi.models;

namespace WebApi.Controllers;

[ApiController]
[Microsoft.AspNetCore.Mvc.Route("identity")]
[Authorize]
public class IdentityController : ControllerBase
{
    public const string DiscoveryUrl = ".well-known/openid-configuration";

    public const string VerificationStateString = "Verification state";

    //between 45 and 128 characters! it *should* be cryptographically random. See https://www.oauth.com/oauth2-servers/pkce/authorization-request/
    public const string CodeVerifier = "this_is_a_verifier_string_que_tiene_que_tener_mas_de_45_caracteres";
    private readonly ILogger<IdentityController> _logger;
    private readonly LinkGenerator _linkGenerator;
    private readonly string _serverUrl;
    private readonly HttpClient _client;
    private DiscoveryDocumentResponse? _discoveryDoc;
    private string _pkce;

    public IdentityController(IConfiguration configuration,
        ILogger<IdentityController> logger,
        LinkGenerator linkGenerator)
    {
        _logger = logger;
        _linkGenerator = linkGenerator;
        _serverUrl = configuration.GetValue("IdentityServer:url", "https://localhost:4001");
        _client = new HttpClient();
        _discoveryDoc = GetDiscoveryDocument().Result;
    }

    [AllowAnonymous]
    [HttpPost("clientlogin")]
    [SwaggerOperation(
        Summary = "ClientCredentials flow",
        Description = "Gets an access token from the identity server using CLIENT CREDENTIALS flow",
        Tags = new[] {"IdentityServer Tokens"}
    )]
    public async Task<IActionResult> Login([FromBody] LoginModel login)
    {
        // get a token from identity server using ClientCredentials flow
        // use client_id / secret
        var discoveryDoc = await GetDiscoveryDocument();

        _logger.LogInformation("{DiscoveryDoc}", discoveryDoc);

        // 2. get the url to call to get the token from the discovery doc
        // (a) using IdentityModel library
        var tokenEndpoint = discoveryDoc.TokenEndpoint;
        var tokenStr = await _client.RequestClientCredentialsTokenAsync(
            new ClientCredentialsTokenRequest()
            {
                Address = tokenEndpoint,
                ClientId = login.ClientId,
                ClientSecret = login.ClientSecret,
                Scope = "api1.read"
            });

        return Ok(tokenStr);
    }

    [AllowAnonymous]
    [HttpGet("code/{pkce:bool}")]
    [SwaggerOperation(
        Summary = "Code flow",
        Description = "Gets an access token from the identity server using CODE (with optional PKCE) flow",
        Tags = new[] {"IdentityServer Tokens"}
    )]
    public async Task<IActionResult> AuthorizationCode(bool pkce = false)
    {
        // get a token from identity server using Authorization Code flow
        var discoveryDoc = await GetDiscoveryDocument();
        // 2. get code from the server
        var reqUrl = new RequestUrl(discoveryDoc.AuthorizeEndpoint);
        var pkceStr = pkce ? GetCodeChallenge() : null;
        var codeUrl = reqUrl.CreateAuthorizeUrl(
            clientId: pkce ? "client_pkce" : "client_code",
            responseType: OidcConstants.ResponseTypes.Code,
            redirectUri: _linkGenerator.GetUriByAction(HttpContext, pkce ? nameof(GetTokenFromCodePkce) : nameof(GetTokenFromCode)),
            state: VerificationStateString,
            scope: "openid api1.read",
            codeChallenge: pkceStr,
            codeChallengeMethod: pkce ? OidcConstants.CodeChallengeMethods.Sha256 : null
        );
        _logger.LogInformation("Authorization request: {AuthRequest}", codeUrl);
        return Redirect(codeUrl);
    }

    private string GetCodeChallenge()
    {
        using var sha256 = SHA256.Create();
        var challengeBytes = sha256.ComputeHash(Encoding.ASCII.GetBytes(CodeVerifier));
        return Base64Url.Encode(challengeBytes);
    }

    [AllowAnonymous]
    [HttpGet("private/tokenfromcode")]
    [SwaggerOperation(
        Summary = "Code flow",
        Description = "Endpoint to be called by the identity server with a code, connects again to get the token",
        Tags = new[] {"IdentityServer Tokens"}
    )]
    public async Task<IActionResult> GetTokenFromCode([FromQuery] string code, [FromQuery] string state)
    {
        _logger.LogInformation("RedirectUrl called with code={Code}", code);
        if (state != VerificationStateString)
            throw new BadHttpRequestException("State is wrong!");

        _logger.LogInformation("Action uri: {ActionUri}", Url.Action(nameof(GetTokenFromCode)));
        var discoveryDoc = GetDiscoveryDocument();
        var authCodeRequest = new AuthorizationCodeTokenRequest()
        {
            Address = discoveryDoc.Result.TokenEndpoint,
            Code = code,
            ClientId = "client_code",
            ClientSecret = "secret",
            CodeVerifier = null,
            RedirectUri = _linkGenerator.GetUriByAction(HttpContext)
        };
        var tokenResponse = await _client.RequestAuthorizationCodeTokenAsync(authCodeRequest);
        if (tokenResponse.IsError)
            throw new BadHttpRequestException(tokenResponse.Error);

        _logger.LogInformation("Token response: {TokenResponse}", tokenResponse);

        return Ok(tokenResponse);
    }

    [AllowAnonymous]
    [HttpGet("private/tokenfromcodepkce")]
    [SwaggerOperation(
        Summary = "Code flow-PKCE",
        Description = "Endpoint to be called by the identity server with a code, connects again to get the token",
        Tags = new[] {"IdentityServer Tokens"}
    )]
    public async Task<IActionResult> GetTokenFromCodePkce([FromQuery] string code, [FromQuery] string state)
    {
        _logger.LogInformation("RedirectUrl (pkce) called with code={Code}", code);
        if (state != VerificationStateString)
            throw new BadHttpRequestException("State is wrong!");

        _logger.LogInformation("Action uri: {ActionUri}", Url.Action(nameof(GetTokenFromCode)));
        var discoveryDoc = GetDiscoveryDocument();
        var authCodeRequest = new AuthorizationCodeTokenRequest()
        {
            Address = discoveryDoc.Result.TokenEndpoint,
            Code = code,
            ClientId = "client_pkce",
            ClientSecret = "secret",
            CodeVerifier = CodeVerifier,
            RedirectUri = _linkGenerator.GetUriByAction(HttpContext)
        };
        var tokenResponse = await _client.RequestAuthorizationCodeTokenAsync(authCodeRequest);
        if (tokenResponse.IsError)
            throw new BadHttpRequestException(tokenResponse.Error);

        _logger.LogInformation("Token response: {TokenResponse}", tokenResponse);

        return Ok(tokenResponse);
    }

    [HttpGet("claims")]
    [SwaggerOperation(
        Summary = "List user claims",
        Description = "Gets a list of current logged-in user's claims",
        Tags = new[] {"AspNet Core Identity"}
    )]
    public IActionResult GetClaims()
    {
        return Ok(User.Claims.Select(c => new {c.Type, c.Value, c.ValueType}).ToArray());
    }

    /// <summary>
    /// Retrieves the discovery document from the server and caches it in private property
    /// </summary>
    /// <returns></returns>
    /// <exception cref="BadHttpRequestException"></exception>
    private async Task<DiscoveryDocumentResponse> GetDiscoveryDocument()
    {
        // (a) using IdentityModel library
        if (_discoveryDoc == null)
        {
            _discoveryDoc = await _client.GetDiscoveryDocumentAsync($"{_serverUrl}/{DiscoveryUrl}");
            if (_discoveryDoc.IsError)
                throw new BadHttpRequestException(_discoveryDoc.Error);
        }

        // (b) using plain HttpClient 
        // var discoveryStr = await client.GetStringAsync($"{serverUrl}/{DiscoveryUrl}");
        // var discoveryDoc = JsonNode.Parse(discoveryStr);
        return _discoveryDoc;
    }
}