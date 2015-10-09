using Autofac;
using BrockAllen.MembershipReboot;
using BrockAllen.MembershipReboot.Ef;
using BrockAllen.MembershipReboot.Owin;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.OAuth;
using Owin;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;
using System.Web.Http;

namespace ServerApp
{
    public class Startup
    {
        public static OAuthBearerAuthenticationOptions oauthConfig { get; private set; }

        public void Configuration(IAppBuilder app)
        {
            ConfigureMembershipReboot(app);

            var oauthServerConfig = new Microsoft.Owin.Security.OAuth.OAuthAuthorizationServerOptions
            {
                AllowInsecureHttp = true,
                Provider = new MyProvider(),
                TokenEndpointPath = new PathString("/token")
            };
            app.UseOAuthAuthorizationServer(oauthServerConfig);

            oauthConfig = new Microsoft.Owin.Security.OAuth.OAuthBearerAuthenticationOptions
            {
                AuthenticationMode = Microsoft.Owin.Security.AuthenticationMode.Active,
                AuthenticationType = "Bearer"
            };
            app.UseOAuthBearerAuthentication(oauthConfig);

            var config = new HttpConfiguration();
            config.MapHttpAttributeRoutes();
            app.UseWebApi(config);
        }

        private static void ConfigureMembershipReboot(IAppBuilder app)
        {
            System.Data.Entity.Database.SetInitializer(new System.Data.Entity.MigrateDatabaseToLatestVersion<DefaultMembershipRebootDatabase, BrockAllen.MembershipReboot.Ef.Migrations.Configuration>());

            var builder = new ContainerBuilder();

            var config = new MembershipRebootConfiguration();
            // just for giggles, we'll use the multi-tenancy to keep
            // client authentication separate from user authentication
            config.MultiTenant = true;
            config.RequireAccountVerification = false;

            config.VerificationKeyLifetime = new TimeSpan(0, 40, 0);
            
            builder.RegisterInstance(config);

            builder.RegisterType<DefaultMembershipRebootDatabase>()
                .InstancePerLifetimeScope();
            
            builder.RegisterType<DefaultUserAccountRepository>()
                .As<IUserAccountRepository>()
                .As<IUserAccountQuery>()
                .InstancePerLifetimeScope();

            builder.RegisterType<UserAccountService>()
                .InstancePerLifetimeScope();

            var container = builder.Build();
            app.Use(async (ctx, next) =>
            {
                using (var scope = container.BeginLifetimeScope())
                {
                    ctx.Environment.SetUserAccountService(() => scope.Resolve<UserAccountService>());
                    await next();
                }
            });

            PopulateTestData(container);
        }

        private static void PopulateTestData(IContainer container)
        {
            using(var scope = container.BeginLifetimeScope())
            {
                var svc = scope.Resolve<UserAccountService>();
                //if (svc.GetByUsername("clients", "client") == null)
                //{
                //    var client = svc.CreateAccount("clients", "client", "secret", (string)null);
                //    svc.AddClaim(client.ID, "scope", "foo");
                //    svc.AddClaim(client.ID, "scope", "bar");
                //}
                //if (svc.GetByUsername("users", "alice") == null)
                //{
                //    var alice = svc.CreateAccount("users", "alice", "pass", "alice@alice.com");
                //    svc.AddClaim(alice.ID, "role", "people");
                //}
                if (svc.GetByUsername("clients", "client") == null)
                {
                    var client = svc.CreateAccount("clients", "client", "secret", (string)null);
                    svc.AddClaim(client.ID, "scope", "foo");
                    svc.AddClaim(client.ID, "scope", "bar");
                }
                if (svc.GetByUsername("users", "alice") == null)
                {
                    var alice = svc.CreateAccount("users", "alice", "pass", "alice@alice.com");
                    svc.AddClaim(alice.ID, "role", "people");
                }
                if (svc.GetByUsername("users", "sopyan") == null)
                {
                    var alice = svc.CreateAccount("users", "sopyan", "pass", "alice2@alice.com");
                    svc.AddClaim(alice.ID, "role", "people");
                }
            }
        }
    }

    public class MyProvider : OAuthAuthorizationServerProvider
    {
        public override System.Threading.Tasks.Task ValidateClientAuthentication(OAuthValidateClientAuthenticationContext context)
        {
            //string cid, csecret;
            //if (context.TryGetBasicCredentials(out cid, out csecret))
            //{
            //    var svc = context.OwinContext.Environment.GetUserAccountService<UserAccount>();
            //    if (svc.Authenticate("users", cid, csecret))
            //    {
            //        context.Validated();
            //    }
            //}

            /* 
             * We should be not use this method,
             * becuse this methos used for Basic Authenticate.
             * So for validate context, we use this condition :)
            */

            if (context.ClientId == null)
            {
                context.Validated();
            }
            return Task.FromResult<object>(null);
        }

        public override Task ValidateTokenRequest(OAuthValidateTokenRequestContext context)
        {
            if (context.TokenRequest.IsResourceOwnerPasswordCredentialsGrantType)
            {
                var svc = context.OwinContext.Environment.GetUserAccountService<UserAccount>();
                //var client = svc.GetByUsername("users", context.Request.ReadFormAsync().Result["username"]);
                //var scopes = context.TokenRequest.ResourceOwnerPasswordCredentialsGrant.Scope;
                //if (scopes.All(scope=>client.HasClaim("role", "people")))
                //{
                //    context.Validated();
                //}

                /* Custom validation for authenticated client to request access token */
                var client = svc.GetByUsername(context.TokenRequest.ResourceOwnerPasswordCredentialsGrant.UserName);
                if (svc.Authenticate("users", context.TokenRequest.ResourceOwnerPasswordCredentialsGrant.UserName, context.TokenRequest.ResourceOwnerPasswordCredentialsGrant.Password))
                {
                    context.Validated();
                }
            }
            return Task.FromResult<object>(null);
        }

        public override Task GrantResourceOwnerCredentials(OAuthGrantResourceOwnerCredentialsContext context)
        {
            var svc = context.OwinContext.Environment.GetUserAccountService<UserAccount>();
            UserAccount user;

            if (svc.Authenticate("users", context.UserName, context.Password, out user))
            {
                var claims = user.GetAllClaims();
                //var id = new System.Security.Claims.ClaimsIdentity(claims, "MembershipReboot");

                var tokenExpire = TimeSpan.FromMinutes(5);
                ClaimsIdentity identity = new ClaimsIdentity(OAuthDefaults.AuthenticationType);
                identity.AddClaim(new Claim(ClaimTypes.Name, context.UserName));
                identity.AddClaim(new Claim(ClaimTypes.Role, claims.GetValue("role")));
                //var prop = new AuthenticationProperties()
                //{
                //    IssuedUtc = DateTime.UtcNow,
                //    ExpiresUtc = DateTime.UtcNow.Add(tokenExpire)
                //};
                //var ticket = new AuthenticationTicket(identity, prop);
                AuthenticationProperties properties = CreateProperties(context.UserName, claims.GetValue("role"));
                properties.IssuedUtc = DateTime.UtcNow;
                properties.ExpiresUtc = DateTime.UtcNow.Add(tokenExpire);
                AuthenticationTicket ticket = new AuthenticationTicket(identity, properties);
                context.Validated(ticket);
            }
            else
            {
                context.SetError("invalid_grant", "The user name or password is incorrect.");
            }
            
            return base.GrantResourceOwnerCredentials(context);
        }

        public override Task TokenEndpoint(OAuthTokenEndpointContext context)
        {
            foreach (KeyValuePair<string, string> property in context.Properties.Dictionary)
            {
                context.AdditionalResponseParameters.Add(property.Key, property.Value);
            }

            return Task.FromResult<object>(null);
        }

        public static AuthenticationProperties CreateProperties(string userName, string role)
        {
            IDictionary<string, string> data = new Dictionary<string, string>
            {
                { "userName", userName },
                { "role", role }
            };
            return new AuthenticationProperties(data);
        }
    }
}