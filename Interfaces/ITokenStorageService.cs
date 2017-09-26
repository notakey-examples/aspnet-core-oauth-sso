/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OAuth.Providers
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using Mvc.Client.Models;
using Mvc.Client.Interfaces;

namespace Mvc.Client.Interfaces
{
    public interface ITokenStorageService
    {


        void saveAccessToken ( string accessToken);
        void saveRefreshToken( string refreshToken);
        void saveExpirationTime(TimeSpan expires);

		string getAccessToken( );
		string getRefreshToken();
		DateTime getExpirationTime( );
	

	}
}