using System;
using System.Configuration;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Web;
using System.Web.Mvc;
using IdentityModel.Client;

namespace KeycloakAuth.Helper
{
    [AttributeUsage(AttributeTargets.Method, AllowMultiple = true, Inherited = true)]
    public class ExirAuthorize : AuthorizeAttribute
    {
       
        protected override bool AuthorizeCore(HttpContextBase httpContext)
        {
            if (!httpContext.User.Identity.IsAuthenticated ||
                DateTime.Parse(
                    ((ClaimsPrincipal)httpContext.User).Claims.First(c => c.Type == "expires_at").Value).ToUniversalTime() <
                DateTime.Now.ToUniversalTime())
            {
                return false;
            }

            var token = ((ClaimsPrincipal)httpContext.User).Claims.First(c => c.Type == "access_token").Value;
            var httpClient = new HttpClient();
            UserInfoRequest userInfoRequest = new UserInfoRequest
            {
                Address = ConfigurationManager.AppSettings["KeycloakUrl"] + "protocol/openid-connect/userinfo",
                Token = token
            };

            var userInfoResponse = httpClient.GetUserInfoAsync(userInfoRequest).Result;

            if (userInfoResponse.IsError)
                return false;

            return base.AuthorizeCore(httpContext);
        }

    }
}