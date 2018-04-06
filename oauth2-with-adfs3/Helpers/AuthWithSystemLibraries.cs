using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Web;

namespace oauth2_with_adfs3.Helpers
{
    /// <summary>
    /// This was converted from VB very quickly, refactoring recommended
    /// </summary>
    public class AuthWithSystemLibraries
    {
        public string GetOAuthToken(
            string username,
            string password,
            string clientId,
            string redirectUri,
            string crmUrl)
        {
            var cookies = new CookieContainer();

            #region Retrieve authorization URL dynamically instead of hard coding ADFS url
            var request = (HttpWebRequest)WebRequest.Create(crmUrl);
            request.AllowAutoRedirect = false;
            request.Method = "HEAD";
            request.CookieContainer = cookies;
            request.ContentType = "application/x-www-form-urlencoded";
            HttpWebResponse response;

            // Will retrieve http error 401, needs to be handled to retrieve headers
            try
            {
                response = (HttpWebResponse)request.GetResponse();
            }
            catch (WebException ex)
            {
                response = (HttpWebResponse)ex.Response;
            }

            var authHeaders = response.Headers["WWW-Authenticate"].Split(',');
            var authorizationUrl = authHeaders[0].Split('=')[1];
            var resourceId = authHeaders[1].Split('=')[1];

            #endregion

            #region Set cookies and retrieve auth code
            var authCodeUrl = authorizationUrl +
                              "?response_type=code" +
                              "&client_id=" + clientId +
                              "&resource=" + HttpUtility.UrlEncode(resourceId) +
                              "&redirect_uri=" + HttpUtility.UrlEncode(redirectUri);

            var code = string.Empty;

            // First run to set cookies, second to retrieve authorization code
            for (var i = 0; i < 2; i++)
            {
                request = (HttpWebRequest)WebRequest.Create(authCodeUrl);
                request.Method = "POST";
                request.AllowAutoRedirect = false;
                request.PreAuthenticate = true;
                request.ContentType = "application/x-www-form-urlencoded";
                request.CookieContainer = cookies;

                using (var stOut = new StreamWriter(request.GetRequestStream(), Encoding.ASCII))
                {

                    var requestContent = "UserName=" + HttpUtility.UrlEncode(username) + "&Password=" +
                                         HttpUtility.UrlEncode(password) + "&AuthMethod=FormsAuthentication";

                    stOut.WriteLine(requestContent);
                }

                response = (HttpWebResponse)request.GetResponse();

                cookies.Add(response.Cookies);
                code = response.Headers["Location"].Split('=').Last();

            }

            #endregion

            #region Retrieve OAuth2.0 bearer token

            request = (HttpWebRequest)WebRequest.Create(authorizationUrl.Replace("authorize", "token"));
            request.Headers.Add("Cache-Control", "no-cache");
            request.ContentType = "application/x-www-form-urlencoded";
            request.AllowAutoRedirect = false;
            request.Method = "POST";
            request.Headers.Add(HttpRequestHeader.AcceptEncoding, "gzip, deflate");
            request.Accept = "*/*";
            request.CookieContainer = cookies;
            var requestString = "client_id=" + clientId +
                                "&grant_type=authorization_code&code=" + code +
                                "&redirect_uri=" + HttpUtility.UrlEncode(redirectUri);
            var requestBody = Encoding.UTF8.GetBytes(requestString);
            request.ContentLength = requestBody.Length;
            string responseValues;
            using (var stOut = request.GetRequestStream())
            {
                stOut.Write(requestBody, 0, requestBody.Length);
                response = (HttpWebResponse)request.GetResponse();
                using (var sr = new StreamReader(response.GetResponseStream()))
                {
                    /*
                     Returns JSON in format:
                        { "access_token":"<token_here>","token_type":"bearer","expires_in":36000 }
                    */
                    responseValues = sr.ReadToEnd();
                }
            }

            #endregion

            #region Extract bearer token

            responseValues = responseValues.Replace("\"", "").Replace("{", "").Replace("}", "");
            var rawValuesArray = responseValues.Split(',');
            var values = new Dictionary<string, string>();
            foreach (var keyValuePair in rawValuesArray)
            {
                var splitValuePair = keyValuePair.Split(':');
                values.Add(splitValuePair.First(), splitValuePair.Last());
            }

            var token = values["access_token"];
            return token;

            #endregion
        }

        public bool TestToken(string apiUrl, string token)
        {
            var request = WebRequest.Create(apiUrl + "/WhoAmI");
            request.Headers.Add("Authorization", "Bearer " + token);
            request.Headers.Add("OData-Version", "4.0");
            request.Headers.Add("OData-MaxVersion", "4.0");
            request.ContentType = "application/json";

            try
            {
                request.GetResponse();
                return true;
            }
            catch
            {
                return false;
            }
        }
    }
}
