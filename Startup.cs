/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OAuth.Providers
 * for more information concerning the license and the contributors participating to this project.
 */
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using System.Net.Http.Headers;
using System.Dynamic;
using System.Net.Http;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.Authentication.OAuth;
using Mvc.Client.Interfaces;


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

            services.AddSingleton<IHttpContextAccessor, HttpContextAccessor>();

            services.AddMvc();

            services.AddDistributedMemoryCache();

			services.AddSession(options =>
                {
                    // Set a short timeout for easy testing.
                    options.IdleTimeout = TimeSpan.FromSeconds(3600);
                    options.CookieHttpOnly = true;
                    options.CookieName = "LocalSessionCookie";
                }
            );
			
            services.AddTransient<ITokenStorageService, TokenStorageService>();
            services.AddTransient<TokenStorageService>();

		}

        public void Configure(IApplicationBuilder app, IServiceProvider serviceProvider , ITokenStorageService tsp, IHttpContextAccessor httpContextAccessor)
        {
            app.UseStaticFiles();

            app.UseSession();

			app.UseCookieAuthentication(new CookieAuthenticationOptions
			{
				AutomaticAuthenticate = true,
				AutomaticChallenge = true,
                CookieName = "LocalAuthCookie",
				LoginPath = new PathString("/signin"),
                AccessDeniedPath = new PathString("/?err=Access%20denied"),
				LogoutPath = new PathString("/signout")
			});


			//var httpContextAccessor = serviceProvider.GetService<IHttpContextAccessor>();
			//SLO link https://sso.demo.notakey.com/sso/saml2/idp/initSLO.php?RelayState=http://localhost:5000/                                         
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
				Events = new OAuthEvents
                {
                    OnCreatingTicket = async context => { await CreateAuthTicket(context, tsp, httpContextAccessor); },

					OnRemoteFailure = context => {
						context.Response.Redirect("/?err=" + UrlEncoder.Default.Encode(context.Failure.Message)); 
                        context.HandleResponse();
						return Task.FromResult(0);
					}
                }
            });

            app.UseMvc();

        }

        private async Task CreateAuthTicket(OAuthCreatingTicketContext context, ITokenStorageService tsp, IHttpContextAccessor htc)
		{
			// Get the User info using the bearer token
			var request = new HttpRequestMessage()
			{
				RequestUri = new Uri(context.Options.UserInformationEndpoint),
				Method = HttpMethod.Get
			};

			request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", context.AccessToken);
			request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

			var response = await context.Backchannel.SendAsync(request, context.HttpContext.RequestAborted);
			response.EnsureSuccessStatusCode();

			var converter = new ExpandoObjectConverter();
			dynamic user = JsonConvert.DeserializeObject<ExpandoObject>(await response.Content.ReadAsStringAsync(), converter);

            Console.WriteLine("Added username: " + user.username);
            context.Identity.AddClaim(new Claim(ClaimsIdentity.DefaultNameClaimType, user.username));


            try
            {

                IEnumerable attrs = (IEnumerable)user.attributes;
                foreach (KeyValuePair<string, object> u in attrs)
                {
                    List<Object> attr = (List<Object>)u.Value;

                    Console.WriteLine(u.Key + ": " + attr[0]);

                    if(u.Key == "mail"){
                        context.Identity.AddClaim(new Claim(ClaimTypes.Email, (string)attr[0]));
					}
					if (u.Key == "lastName")
					{
						context.Identity.AddClaim(new Claim(ClaimTypes.Surname, (string)attr[0]));
					}
					if (u.Key == "firstName")
					{
                        context.Identity.AddClaim(new Claim(ClaimTypes.GivenName, (string)attr[0]));
					}
					if (u.Key == "mainPhone")
					{
                        context.Identity.AddClaim(new Claim(ClaimTypes.MobilePhone, (string)attr[0]));
					}
					if (u.Key == "guid")
					{
                        context.Identity.AddClaim(new Claim(ClaimTypes.Sid, (string)attr[0]));
					}
					if (u.Key == "authId")
					{
						context.Identity.AddClaim(new Claim("auth-id", (string)attr[0]));
					}

                }
            }
			catch (Exception ex)
			{
                    Console.WriteLine(ex.Message);
			}

            tsp.saveRefreshToken(context.RefreshToken);
            tsp.saveAccessToken(context.AccessToken);
            tsp.saveExpirationTime((TimeSpan)context.ExpiresIn);


			//var dateFirstSeen = DateTime.Now;
			//var serialisedDate = JsonConvert.SerializeObject(dateFirstSeen);
			////AppContext.Session.SetString("RefreshToken", context.RefreshToken);

			////RefreshToken = context.RefreshToken;
			////TokenType = context.TokenType;
			//ExpiresIn = (TimeSpan)context.ExpiresIn;
			//AccessToken = context.AccessToken;

		}

    }
}