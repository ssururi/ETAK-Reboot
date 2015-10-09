using Microsoft.Owin.Security;
using Microsoft.Owin.Security.OAuth;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Security.Claims;
using System.Web;
using System.Web.Http;

namespace ServerApp
{
    
    [Route("test")]
    [Authorize]
    public class TestController : ApiController
    {     
        public IHttpActionResult Get()
        {
            //var cp = User as ClaimsPrincipal;
            //return Ok(cp.Claims.Select(x => new { x.Type, x.Value }));

            Collection<Feature> collFeature = new Collection<Feature>();
            //if (role == "adminCSR")
            //{
                Feature feature = new Feature();
                feature.FeatureName = "Dashboard";
                feature.Link = "CSR/Customer/App/SearchPage";
                feature.LabelForBreadcrumb = "Dashboard Customer";

                collFeature.Add(feature);
            //}

            var tokenExpire = TimeSpan.FromMinutes(5);
            ClaimsIdentity identity = new ClaimsIdentity(OAuthDefaults.AuthenticationType);
            identity.AddClaim(new Claim(ClaimTypes.Name, "alice"));
            var prop = new AuthenticationProperties()
            {
                IssuedUtc = DateTime.UtcNow,
                ExpiresUtc = DateTime.UtcNow.Add(tokenExpire)
            };
            var ticket = new AuthenticationTicket(identity, prop);
            var accessToken = Startup.oauthConfig.AccessTokenFormat.Protect(ticket);

            feature.TokenType = "Bearer";
            feature.AccessToken = accessToken;
            feature.Issued = ticket.Properties.IssuedUtc.ToString();
            feature.Expired = ticket.Properties.ExpiresUtc.ToString();


            return Ok(collFeature);
        }
    }

    public class Feature
    {
        private string _featureName = "";
        private string _link = "";
        private string _labelForBreadcrumb = "";

        private string _tokenType = "";
        private string _accessToken = "";
        private string _issued = "";
        private string _expired = "";

        public string FeatureName { get { return _featureName; } set { _featureName = value; } }
        public string Link { get { return _link; } set { _link = value; } }
        public string LabelForBreadcrumb { get { return _labelForBreadcrumb; } set { _labelForBreadcrumb = value; } }
        public string TokenType { get { return _tokenType; } set { _tokenType = value; } }
        public string AccessToken { get { return _accessToken; } set { _accessToken = value; } }
        public string Issued { get { return _issued; } set { _issued = value; } }
        public string Expired { get { return _expired; } set { _expired = value; } }

    }
}