using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace WCFServiceWebRole1
{
    /// <summary>
    /// User Name Password Validator
    /// </summary>
    public class UserValidator
    {
        public bool IsUserValid(string userName, string password, out string commaSeparatedRoles)
        {
            commaSeparatedRoles = string.Empty;
            bool result = false;
            if ((userName == "pipiak") && (password == "322332"))
            {
                commaSeparatedRoles = "Read,Write";
                result = true;
            }
            else if ((userName == "pipiak") && (password == "12345"))
            {
                commaSeparatedRoles = "Read";
                result = true;
            }
            else
            {
                result = false;
            }
            
            return result;
        }
    }
}