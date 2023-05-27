using System;
using System.Collections.Generic;
using System.Configuration;
using System.Globalization;
using System.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http;
using System.Security.Authentication;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web.Configuration;
using IdentityModel;
using IdentityModel.Client;
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
            JwtSecurityTokenHandler.DefaultInboundClaimTypeMap = new Dictionary<string, string>();

            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationType = "oidc",
                ExpireTimeSpan = TimeSpan.FromMinutes(30),
                SlidingExpiration = true
            });

            app.UseOpenIdConnectAuthentication(new OpenIdConnectAuthenticationOptions
            {
                
                Authority = ConfigurationManager.AppSettings["KeycloakUrl"],
                RequireHttpsMetadata = false,
                ClientId = ConfigurationManager.AppSettings["KeycloakClientId"],
                //ClientSecret = WebConfigurationManager.AppSettings["clientSecret"].ToString(),
                ResponseType = OpenIdConnectResponseType.CodeIdTokenToken,
                Scope ="openid attribute microprofile-jwt roles profile web-origins email address phone",
                RedirectUri = "http://localhost:4000/",
                PostLogoutRedirectUri = "http://localhost:4000/",
                UseTokenLifetime = true,
                SignInAsAuthenticationType = "oidc",
                AuthenticationType = "oidc",                
                RefreshOnIssuerKeyNotFound = false,
                
                Notifications = new OpenIdConnectAuthenticationNotifications
                {
                    AuthorizationCodeReceived = async n =>
                    {
                        var client = new HttpClient();
                        AuthorizationCodeTokenRequest codeTokenRequest = new AuthorizationCodeTokenRequest
                        { 
                            Address =  n.Options.Authority + "protocol/openid-connect/token",
                            ClientId = ConfigurationManager.AppSettings["KeycloakClientId"],
                            //ClientSecret = WebConfigurationManager.AppSettings["clientSecret"].ToString(),
                            Code = n.Code,
                            RedirectUri = n.RedirectUri
                        };
                        var tokenResponse = await client.RequestAuthorizationCodeTokenAsync(codeTokenRequest);
                        if (tokenResponse.IsError)
                        {
                            throw new AuthenticationException(tokenResponse.Error);
                        }
                        UserInfoRequest userInfoRequest = new UserInfoRequest
                        {
                            Address = n.Options.Authority + "protocol/openid-connect/userinfo",
                            Token = tokenResponse.AccessToken
                        };
                        
                        var userInfoResponse = await client.GetUserInfoAsync(userInfoRequest);
                        
                        var id = new ClaimsIdentity(n.AuthenticationTicket.Identity.AuthenticationType);
                        id.AddClaims(userInfoResponse.Claims);

                        id.AddClaim(new Claim("access_token", tokenResponse.AccessToken));
                        id.AddClaim(new Claim("expires_at", DateTime.Now.AddSeconds(tokenResponse.ExpiresIn).ToLocalTime().ToString(CultureInfo.InvariantCulture)));
                        id.AddClaim(new Claim("refresh_token", tokenResponse.RefreshToken));
                        id.AddClaim(new Claim("id_token", n.ProtocolMessage.IdToken));
                        id.AddClaim(new Claim("sid", n.AuthenticationTicket.Identity.FindFirst("sid").Value));

                        n.AuthenticationTicket = new AuthenticationTicket(
                            new ClaimsIdentity(id.Claims, n.AuthenticationTicket.Identity.AuthenticationType, JwtClaimTypes.Name, JwtClaimTypes.Role),
                            n.AuthenticationTicket.Properties
                        );


                    },
                    RedirectToIdentityProvider = n =>
                    {
                        if (n.ProtocolMessage.RequestType !=  Microsoft.IdentityModel.Protocols.OpenIdConnect.OpenIdConnectRequestType.Logout)
                        {
                            return Task.FromResult(0);
                        }

                        var idTokenHint = n.OwinContext.Authentication.User.FindFirst("id_token");

                        if (idTokenHint != null)
                        {
                            n.ProtocolMessage.IdTokenHint = idTokenHint.Value;
                        }

                        return Task.FromResult(0);

                    }
                }
            });
        }
    }
}