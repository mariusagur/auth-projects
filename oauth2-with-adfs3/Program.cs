using System;
using oauth2_with_adfs3.Helpers;
using static System.Configuration.ConfigurationManager;

namespace oauth2_with_adfs3
{
    class Program
    {
        static void Main(string[] args)
        {
            var helper = new AuthWithSystemLibraries();
            var bearerToken = helper.GetOAuthToken(
                                AppSettings["UserName"], 
                                AppSettings["Password"], 
                                AppSettings["ClientId"], 
                                AppSettings["RedirectUrl"], 
                                AppSettings["CrmUrl"]);
            var result = helper.TestToken("apirul", bearerToken);
            Console.WriteLine(result ? "Auth test successful" : "Auth failed");
        }
    }
}
