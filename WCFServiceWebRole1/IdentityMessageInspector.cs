using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.ServiceModel.Dispatcher;
using System.ServiceModel.Channels;
using System.Net;
using System.IO;
using System.ServiceModel;
using System.Security.Principal;
using System.Web.Security;
using System.Threading;
using System.Collections;

namespace WCFServiceWebRole1
{
    public class IdentityMessageInspector : IDispatchMessageInspector
    {
        public object AfterReceiveRequest(ref Message request, System.ServiceModel.IClientChannel channel, System.ServiceModel.InstanceContext instanceContext)
        {
            var messageProperty = (HttpRequestMessageProperty)
                OperationContext.Current.IncomingMessageProperties[HttpRequestMessageProperty.Name];
            string cookie = messageProperty.Headers.Get("Set-Cookie");
            if (cookie == null) // Check for another Message Header - SL applications
            {
                cookie = messageProperty.Headers.Get("Cookie");
            }
            if (cookie == null)
                cookie = string.Empty;

            Hashtable cookieTable = new Hashtable();
            string[] cookieValuePairs = cookie.Split(';');
            foreach (string pair in cookieValuePairs)
            {
                
                string[] splitted = pair.Split(',', '=');
                if (splitted.Length == 1)
                {
                    //only key
                    if (!cookieTable.ContainsKey(splitted[0]))
                    {
                        cookieTable.Add(splitted[0], string.Empty);
                    }
                }
                else if (splitted.Length == 2)
                {
                    if (!cookieTable.ContainsKey(splitted[0]))
                    {
                        cookieTable.Add(splitted[0], splitted[1]);
                    }
                }
                else if (splitted.Length == 4)
                {
                    if (!cookieTable.ContainsKey(splitted[0]))
                    {
                        cookieTable.Add(splitted[0], splitted[1]);
                    }
                }
                else if (splitted.Length == 5)
                {
                    if (!cookieTable.ContainsKey(splitted[1]))
                    {
                        cookieTable.Add(splitted[1], splitted[2]);
                    }
                }
            }

            string encryptedTicket = string.Empty;

            // Set User Name from cookie
            if (cookieTable.ContainsKey(FormsAuthentication.FormsCookieName))
                encryptedTicket = cookieTable[FormsAuthentication.FormsCookieName].ToString();

            FormsAuthenticationTicket ticket = null;
            string userName = string.Empty;
            string roles = string.Empty;

            // Decrypt
            if (!string.IsNullOrEmpty(encryptedTicket))
            {
                ticket = FormsAuthentication.Decrypt(encryptedTicket);
                userName = ticket.Name;
                roles = ticket.UserData;
            }

            // Set Thread Principal to User Name
            if (!string.IsNullOrEmpty(userName))
            {
                CustomIdentity customIdentity = new CustomIdentity();
                GenericPrincipal threadCurrentPrincipal = new GenericPrincipal(customIdentity, roles.Split(','));
                customIdentity.IsAuthenticated = true;
                customIdentity.Name = userName;
                Thread.CurrentPrincipal = threadCurrentPrincipal;
            }

            return null;
        }

        private string[] GetRoles(string value)
        {
            if (!string.IsNullOrEmpty(value))
            {
                List<string> roles = new List<string>();

                int ix = 0;
                foreach (string item in value.Split(';'))
                {
                    if (ix > 0)
                        if (item.Trim().Length > 0)
                            roles.Add(item);

                    ix++;
                }

                return roles.ToArray<string>();
            }

            return new string[0];
        }

        private string GetUserName(string value)
        {
            if (!string.IsNullOrEmpty(value))
            {
                foreach (string item in value.Split(';'))
                    return item;
            }

            return string.Empty;
        }

        public void BeforeSendReply(ref Message reply, object correlationState)
        {

        }
    }
}
