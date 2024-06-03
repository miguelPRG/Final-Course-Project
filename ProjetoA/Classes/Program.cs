using System;
using System.Web;

public partial class Login : System.Web.UI.Page
{
    protected void Page_Load(object sender, EventArgs e)
    {
        if (IsPostBack)
        {
            string username = Request.Form["username"];
            string password = Request.Form["password"];

            if (AuthenticateUser(username, password))
            {
                // Redirect the user to the specified returnUrl after validation
                string returnUrl = Request.QueryString["returnUrl"];
                if (!string.IsNullOrEmpty(returnUrl) && IsLocalUrl(returnUrl))
                { 
                    Response.Redirect(returnUrl);   
                }
                else
                {
                    Response.Redirect("Default.aspx");
                }
            }
            else
            {
                // Authentication failed
                Response.Write("Invalid username or password."); 
            }
        }
    }

    private bool AuthenticateUser(string username, string password)
    {
        // Authentication logic here
        return true; // For the sake of example, we assume authentication is successful
    }

    private bool IsLocalUrl(string url)
    {
        return url.StartsWith("/") && !url.StartsWith("//") && !url.StartsWith("/\\");
    }

    private IActionResult RedirectToLocal(string returnUrl) 
    {
        if (Url.IsLocalUrl(returnUrl))    
        {  
            return Redirect(returnUrl);         
        }
        else
        {
            return RedirectToAction(nameof(HomeController.Index), "Home");
        }
    }
}
