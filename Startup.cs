using System;
using System.Collections.Generic;
using System.Configuration;
using System.Globalization;
using System.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNet.Identity;
using Microsoft.Identity.Client;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OAuth;
using Microsoft.Owin.Security.OpenIdConnect;
using Owin;
using Owin.Security.Keycloak;
using AuthenticationContext = System.Web.Mvc.Filters.AuthenticationContext;

[assembly: OwinStartup(typeof(KeycloakAuth.Startup))]

namespace KeycloakAuth
{
    public class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            IdentityModelEventSource.ShowPII = true;
            // Configure the middleware to use Keycloak for authentication
            JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Clear();
            app.SetDefaultSignInAsAuthenticationType(CookieAuthenticationDefaults.AuthenticationType);
            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationType = CookieAuthenticationDefaults.AuthenticationType
            });
            app.UseOpenIdConnectAuthentication(new OpenIdConnectAuthenticationOptions
            {
                Authority = ConfigurationManager.AppSettings["KeycloakUrl"],
                ClientId = ConfigurationManager.AppSettings["KeycloakClientId"],
                //ClientSecret = ConfigurationManager.AppSettings["KeycloakClientSecret"],
                RedirectUri = "http://localhost:4000/",
                ResponseType = OpenIdConnectResponseType.CodeIdTokenToken,
//                Scope = OpenIdConnectScope.OpenIdProfile,
                Scope ="openid phone microprofile-jwt roles profile web-origins offline_access email address",
                UseTokenLifetime = true,
                RequireHttpsMetadata = false,
                SignInAsAuthenticationType = CookieAuthenticationDefaults.AuthenticationType,
                TokenValidationParameters = new TokenValidationParameters
                {
                    NameClaimType = "preferred_username",
                    ValidateIssuer = false
                },
                Notifications = new OpenIdConnectAuthenticationNotifications
                {
                    SecurityTokenValidated = async n =>
                    {
                        // var userInfoClient = new UserInfoClient(
                        //     new Uri(n.Options.Authority + "/realms/" +
                        //             ConfigurationManager.AppSettings["KeycloakRealm"] +
                        //             "/protocol/openid-connect/userinfo"));
                        // var userInfo = await userInfoClient.GetAsync(
                        //     new UserInfoRequest { Token = n.ProtocolMessage.AccessToken });

                        var identity = new ClaimsIdentity(
                            n.AuthenticationTicket.Identity.AuthenticationType);
                        identity.AddClaims(n.AuthenticationTicket.Identity.Claims);
                        identity.AddClaim(new Claim("access_token", n.ProtocolMessage.AccessToken));
                        identity.AddClaim(new Claim("expires_at",
                            DateTimeOffset.Now.AddSeconds(int.Parse(n.ProtocolMessage.ExpiresIn))
                                .ToString("o", CultureInfo.InvariantCulture)));
                        //identity.AddClaim(new Claim("refresh_token", n.ProtocolMessage.RefreshToken));
                        identity.AddClaim(new Claim("id_token", n.ProtocolMessage.IdToken));

                        n.AuthenticationTicket = new AuthenticationTicket(
                            identity, n.AuthenticationTicket.Properties);
                    },
                    RedirectToIdentityProvider = n =>
                    {
                        if (n.ProtocolMessage.RequestType ==  Microsoft.IdentityModel.Protocols.OpenIdConnect.OpenIdConnectRequestType.Logout)
                        {
                            var idTokenHint = n.OwinContext.Authentication
                                .User.FindFirst("id_token").Value;

                            n.ProtocolMessage.IdTokenHint = idTokenHint;
                            n.ProtocolMessage.PostLogoutRedirectUri =
                                ConfigurationManager.AppSettings["KeycloakPostLogoutRedirectUri"];
                        }

                        return Task.FromResult(0);
                    }
                }
            });
        }
    }
}