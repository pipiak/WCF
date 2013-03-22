using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Security;
using System.Web.SessionState;
using System.ServiceModel.Channels;
using System.Net;
using System.ServiceModel;

namespace WCFServiceWebRole1
{
    public class Global : System.Web.HttpApplication
    {
        protected void Application_Start(object sender, EventArgs e)
        {
            System.Web.ApplicationServices.AuthenticationService.Authenticating +=
                new EventHandler<System.Web.ApplicationServices.AuthenticatingEventArgs>(AuthenticationService_Authenticating);
        }

        void AuthenticationService_Authenticating(object sender, System.Web.ApplicationServices.AuthenticatingEventArgs e)
        {
            string roles = string.Empty;

            e.Authenticated = new UserValidator().IsUserValid(e.UserName, e.Password, out roles);
            e.AuthenticationIsComplete = true;

            if (e.Authenticated)
            {
                FormsAuthenticationTicket ticket = new FormsAuthenticationTicket(
                    1,
                    e.UserName,
                    DateTime.Now,
                    DateTime.Now.AddHours(24),
                    true,
                    roles,
                    FormsAuthentication.FormsCookiePath);

                // Encrypt the ticket using machine key
                string encryptedValue = FormsAuthentication.Encrypt(ticket);

                // Attach Cookie to Operation Context header
HttpResponseMessageProperty response = new HttpResponseMessageProperty();
response.Headers[HttpResponseHeader.SetCookie] = FormsAuthentication.FormsCookieName + "=" + encryptedValue;
OperationContext.Current.OutgoingMessageProperties[HttpResponseMessageProperty.Name] = response;
            }
        }

        private string Concatenate(string userName, IList<string> roles)
        {
            string result = userName + ";";

            foreach (string role in roles)
                result += role + ";";

            return result;
        }

        protected void Session_Start(object sender, EventArgs e)
        {

        }

        protected void Application_BeginRequest(object sender, EventArgs e)
        {

        }

        protected void Application_AuthenticateRequest(object sender, EventArgs e)
        {

        }

        protected void Application_Error(object sender, EventArgs e)
        {

        }

        protected void Session_End(object sender, EventArgs e)
        {

        }

        protected void Application_End(object sender, EventArgs e)
        {

        }
    }
}