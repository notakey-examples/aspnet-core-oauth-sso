/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OAuth.Providers
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using Microsoft.AspNetCore.Http;
using Mvc.Client.Interfaces;
using Mvc.Client.Models;

namespace Mvc.Client
{
    public class TokenStorageService: ITokenStorageService
    {

		private readonly IHttpContextAccessor _httpContextAccessor;

		public TokenStorageService(IHttpContextAccessor hca)
		{
			_httpContextAccessor = hca;
            Console.WriteLine("Initialized TokenStorageService ");
		}


        public void saveAccessToken( string tok ){
            
            _httpContextAccessor.HttpContext.Session.SetString("accessToken", tok);
        }

		public string getAccessToken()
		{
            if(_httpContextAccessor.HttpContext.Session == null){
                return "";
            }
            return _httpContextAccessor.HttpContext.Session.GetString("accessToken");
		}

        public void saveRefreshToken(string tok)
		{
			_httpContextAccessor.HttpContext.Session.SetString("refreshToken", tok);
		}

        public string getRefreshToken()
		{
			if (_httpContextAccessor.HttpContext.Session == null)
			{
				return "";
			}
			return _httpContextAccessor.HttpContext.Session.GetString("refreshToken");
		}

        public void saveExpirationTime(TimeSpan exp)
		{
            DateTimeOffset dt = DateTime.Now.Add(exp);
            Console.WriteLine("TokenStorageService DateTimeOffset: " + dt.ToString());
            Int32 ts = (Int32)dt.ToUnixTimeSeconds();
			Console.WriteLine("TokenStorageService ToUnixTimeSeconds: " + ts);
            _httpContextAccessor.HttpContext.Session.SetInt32("expirationTime", ts);
		}

        public DateTime getExpirationTime()
		{
			if (_httpContextAccessor.HttpContext.Session == null)
			{
                return new DateTime();
			}


			Int32? ts = _httpContextAccessor.HttpContext.Session.GetInt32("expirationTime");

            if( ts == null ){
                return new DateTime();
            }

			DateTimeOffset exp = DateTimeOffset.FromUnixTimeSeconds((long)ts);
            return exp.UtcDateTime;
		}

    }
}