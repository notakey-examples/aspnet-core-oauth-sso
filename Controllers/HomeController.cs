/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OAuth.Providers
 * for more information concerning the license and the contributors participating to this project.
 */

using Microsoft.AspNetCore.Mvc;
using Mvc.Client.Extensions;

namespace Mvc.Client.Controllers
{
    public class HomeController : Controller
    {
        [HttpGet("~/")]
        public ActionResult Index() => View("Index");

		[HttpGet("~/loggedon")]
		public ActionResult LoggedOn() => View("LoggedOn");

		[HttpGet("~/loggedoff")]
        public ActionResult LoggedOff(){
            if(User.Identity.IsAuthenticated){
               Redirect("/");
            }
            return View("LoggedOff");
        } 
    }
}