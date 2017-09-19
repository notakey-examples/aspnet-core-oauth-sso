/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OAuth.Providers
 * for more information concerning the license and the contributors participating to this project.
 */

using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace Mvc.Client
{
    public class Startup
    {
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddAuthentication(options =>
            {
                options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            });

            services.AddMvc();
        }

        public void Configure(IApplicationBuilder app)
        {
            app.UseStaticFiles();

			app.UseCookieAuthentication(new CookieAuthenticationOptions
			{
				AutomaticAuthenticate = true,
				AutomaticChallenge = true,
				LoginPath = new PathString("/signin"),
				LogoutPath = new PathString("/signout")
			});

            app.UseOAuthAuthentication(new OAuthOptions
            {
                DisplayName = "NotakeySSO",
                SaveTokens = true,
                AuthenticationScheme = "Application",
                AuthorizationEndpoint = "https://sso.demo.notakey.com/sso/module.php/oauth2/authorize.php",
                TokenEndpoint = "https://sso.demo.notakey.com/sso/module.php/oauth2/access_token.php",
                UserInformationEndpoint = "https://sso.demo.notakey.com/sso/module.php/oauth2/userinfo.php",
                ClientId = "_62e84e38c015008ae22ca1d11a616c48d72e4b7a9c",
                ClientSecret = "_177efa03b58eaa75001a595930217fd8a12e049509",
                Scope = { "basic" },
                CallbackPath = new PathString("/callback"),
				
            });
          

            app.UseMvc();

        }
    }
}