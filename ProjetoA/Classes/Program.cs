/*using System;
using System.Web;
using System.Web.UI;
using Windows.UI.Xaml.Controls;
using Windows.UI.Xaml;

public partial class XSSExample : Page
{
    protected void Page_Load(object sender, EventArgs e)
    {
        if (!IsPostBack) 
        {
            string userInput = Request.QueryString["input"];  
            if (!string.IsNullOrEmpty(userInput))
            {
                // Escapar a entrada do usuário antes de exibi-l
                string encodedInput = Server.HtmlEncode(userInput);
                Response.Write("Olá, " + encodedInput);
            }
        }
    }
}
*/