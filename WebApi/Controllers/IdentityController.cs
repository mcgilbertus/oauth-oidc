using System.Net.Sockets;
using System.Text.Json.Nodes;
using System.Transactions;
using IdentityModel;
using IdentityModel.Client;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Web;
using Microsoft.AspNetCore.Mvc;
using WebApi.models;

namespace WebApi.Controllers;

[ApiController]
[Microsoft.AspNetCore.Mvc.Route("identity")]
[Authorize]
public class IdentityController : ControllerBase
{
    public const string DiscoveryUrl = ".well-known/openid-configuration";
    public const string VerificationStateString = "Verification state string";
    private readonly ILogger<IdentityController> _logger;
    private readonly LinkGenerator _linkGenerator;
    private readonly string _serverUrl;
    private readonly HttpClient _client;
    private DiscoveryDocumentResponse? _discoveryDoc;

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
    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginModel login)
    {
        // get a token from identity server using ClientCredentials flow
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
                Scope = "api1"
            });

        // (b) using plain HttpClient
        // var tokenUrl = discoveryDoc!["token_endpoint"]?.ToString();
        // var parameters = new Dictionary<string, string>
        // {
        // { "address", tokenUrl },
        // { "client_id", login.ClientId },
        // { "client_secret", login.ClientSecret },
        // { "grant_type", "client_credentials" },
        // { "scope", "api1" }
        // };
        // using var request = new HttpRequestMessage(HttpMethod.Post, tokenUrl);
        // request.Headers.Add("Accept", "application/json");
        // request.Content = new FormUrlEncodedContent(parameters);
        // var tokenResponse = client.SendAsync(request);
        // var tokenStr = await tokenResponse.Result.Content.ReadAsStringAsync();

        return Ok(tokenStr);
    }

    [AllowAnonymous]
    [HttpGet("code")]
    public async Task<IActionResult> AuthorizationCode()
    {
        // get a token from identity server using Authorization Code flow
        var discoveryDoc = await GetDiscoveryDocument();
        // 2. get code from the server
        var reqUrl = new RequestUrl(discoveryDoc.AuthorizeEndpoint);
        var codeUrl = reqUrl.CreateAuthorizeUrl(
            clientId: "client2",
            responseType: OidcConstants.ResponseTypes.Code,
            redirectUri: _linkGenerator.GetUriByAction(HttpContext, nameof(GetTokenFromCode)),
            state: VerificationStateString,
            scope: "openid api1"
        );
        _logger.LogInformation("Authorization request: {AuthRequest}", codeUrl);
        return Redirect(codeUrl);
    }

    [AllowAnonymous]
    [HttpGet("tokenfromcode")]
    public async Task<IActionResult> GetTokenFromCode([FromQuery]string code, [FromQuery]string state)
    {
        _logger.LogInformation("RedirectUrl called with code={Code}",code);
        if (state != VerificationStateString)
            throw new BadHttpRequestException("State is wrong!");

        _logger.LogInformation("Action uri: {ActionUri}", Url.Action(nameof(GetTokenFromCode)));
        var discoveryDoc = GetDiscoveryDocument();
        var tokenResponse = await _client.RequestAuthorizationCodeTokenAsync(
            new AuthorizationCodeTokenRequest()
            {
                Address = discoveryDoc.Result.TokenEndpoint,
                Code = code,
                ClientId = "client2",
                ClientSecret = "secret2",
                RedirectUri = _linkGenerator.GetUriByAction(HttpContext)
            });
        if (tokenResponse.IsError)
            throw new BadHttpRequestException(tokenResponse.Error);
        
        _logger.LogInformation("Token response: {TokenResponse}", tokenResponse);
        
        return Ok(tokenResponse);
    }

    [HttpGet]
    public IActionResult GetClaims()
    {
        return Ok(User.Claims.Select(c => new { c.Type, c.Value }).ToArray());
    }
    
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