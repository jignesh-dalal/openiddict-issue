using Microsoft.AspNetCore;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.IdentityModel.Tokens;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;
using Microsoft.AspNetCore.Authentication;
using OpenIddict.Abstractions;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();

builder.Services
    .AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie()
    .AddOpenIdConnect("oidc", "Demo IdentityServer", options => {
        options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        options.SaveTokens = true;

        options.Authority = "https://demo.duendesoftware.com/";
        options.ClientId = "interactive.confidential";
        options.ClientSecret = "secret";
        options.ResponseType = "code";
        options.CallbackPath = "/External/Callback1";

        //options.TokenValidationParameters = new TokenValidationParameters {
        //    //NameClaimType = "name",
        //    //RoleClaimType = "role"
        //    ValidateIssuerSigningKey = false,
        //    ValidateLifetime = false,
        //    ValidateIssuer = false,
        //    ValidateAudience = false,
        //    ValidateSignatureLast = false,
        //    ValidateActor = false,
        //};
    });

builder.Services
    .AddOpenIddict()
    .AddServer(options => {
        options.AddDevelopmentEncryptionCertificate()
               .AddDevelopmentSigningCertificate();

        options.AllowAuthorizationCodeFlow();

        options.SetAuthorizationEndpointUris("/connect/authorize")
               .SetTokenEndpointUris("/connect/token");

        options.EnableDegradedMode();

        options.UseAspNetCore();

        options.AddEventHandler<ValidateAuthorizationRequestContext>(builder =>
            builder.UseInlineHandler(context => {
                if (!string.Equals(context.ClientId, "console_app", StringComparison.Ordinal)) {
                    context.Reject(
                        error: Errors.InvalidClient,
                        description: "The specified 'client_id' doesn't match a registered application.");

                    return default;
                }

                if (!string.Equals(context.RedirectUri, "http://localhost:7890/", StringComparison.Ordinal)) {
                    context.Reject(
                        error: Errors.InvalidClient,
                        description: "The specified 'redirect_uri' is not valid for this client application.");

                    return default;
                }

                return default;
            }));

        options.AddEventHandler<ValidateTokenRequestContext>(builder =>
            builder.UseInlineHandler(context => {
                if (!string.Equals(context.ClientId, "console_app", StringComparison.Ordinal)) {
                    context.Reject(
                        error: Errors.InvalidClient,
                        description: "The specified 'client_id' doesn't match a registered application.");

                    return default;
                }

                // This demo is used by a single public client application.
                // As such, no client secret validation is performed.

                return default;
            }));

        options.AddEventHandler<HandleAuthorizationRequestContext>(builder =>
            builder.UseInlineHandler(async context => {
                var request = context.Transaction.GetHttpRequest() ??
                    throw new InvalidOperationException("The ASP.NET Core request cannot be retrieved.");

                // Retrieve the security principal created by the Steam handler and stored in the authentication cookie.
                // If the principal cannot be retrieved, this indicates that the user is not logged in. In this case,
                // an authentication challenge is triggered to redirect the user to Steam's authentication endpoint.
                var principal = (await request.HttpContext.AuthenticateAsync("oidc"))?.Principal;
                if (principal == null) {
                    await request.HttpContext.ChallengeAsync("oidc");
                    context.HandleRequest();

                    return;
                }

                var identity = new ClaimsIdentity(TokenValidationParameters.DefaultAuthenticationType);

                // Use the "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier" claim
                // (added by the Steam handler to store the user identifier) as the OIDC "sub" claim.
                identity.AddClaim(new Claim(Claims.Subject, principal.GetClaim(ClaimTypes.NameIdentifier)));

                // If needed, you can copy more claims from the cookies principal to the bearer principal.
                // To get more claims from the Steam handler, you'll need to set the application key.

                // Mark all the added claims as being allowed to be persisted in the access token,
                // so that the API controllers can retrieve them from the ClaimsPrincipal instance.
                foreach (var claim in identity.Claims) {
                    claim.SetDestinations(Destinations.AccessToken);
                }

                // Attach the principal to the authorization context, so that an OpenID Connect response
                // with an authorization code can be generated by the OpenIddict server services.
                context.Principal = new ClaimsPrincipal(identity);
            }));

    })

    .AddValidation(options => {
        options.UseLocalServer();
        options.UseAspNetCore();
    });



var app = builder.Build();

app.UseHttpsRedirection();

app.UseRouting();

app.UseAuthentication();

app.UseAuthorization();

app.UseEndpoints(endpoints => {
    endpoints.MapControllers();
});

app.Run();
