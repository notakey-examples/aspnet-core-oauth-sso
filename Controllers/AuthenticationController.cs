/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OAuth.Providers
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http.Authentication;
using Microsoft.AspNetCore.Mvc;
using Mvc.Client.Extensions;
using Mvc.Client.Interfaces;

namespace Mvc.Client.Controllers
{
    public class AuthenticationController : Controller
    {

        [HttpGet("~/signin")]
        public IActionResult SignIn() => View("SignIn", HttpContext.GetExternalProviders());


		[HttpPost("~/signin")]
        public IActionResult SignIn([FromForm] string provider)
        {
            // Note: the "provider" parameter corresponds to the external
            // authentication provider choosen by the user agent.
            if (string.IsNullOrWhiteSpace(provider))
            {
                return BadRequest();
            }

            if (!HttpContext.IsProviderSupported(provider))
            {
                return BadRequest();
            }

			// Instruct the middleware corresponding to the requested external identity
			// provider to redirect the user agent to its own authorization endpoint.
			// Note: the authenticationScheme parameter must match the value configured in Startup.cs
			// Note: RedirectUri instructs Oauth middleware to return to configured location
			return Challenge(new AuthenticationProperties { RedirectUri = "/loggedon" }, provider);
        }

        [HttpGet("~/completesignout")]
        public IActionResult CompleteSignOut()
        {

			if (!User.Identity.IsAuthenticated)
			{
				return Redirect("/loggedoff");
			}

			// Just to check if local session really is destroyed

		    return Redirect("/");

        }

        [HttpPost("~/signout"), HttpGet("~/signout")]
        public IActionResult SignOut()
        {
            // Initiate remote logout procedure on SSO IdP
            // RelayState URLs have to be registered with SSO
            // application to prevent scripted session destruction

            // This instructs the cookies auth middleware to delete the local cookie
            // and redirect user agent to external external identity provider

            HttpContext.Authentication.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

            return Redirect("https://sso.demo.notakey.com/sso/saml2/idp/initSLO?RelayState=http://" + HttpContext.Request.Host + "/completesignout");

            // The Controllerbase.SignOut is broken and will not redirect
			//return SignOut(new AuthenticationProperties { RedirectUri = "/" },
			//CookieAuthenticationDefaults.AuthenticationScheme );

		}
    }
}