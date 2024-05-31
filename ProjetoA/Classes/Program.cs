/*using System;
using System.Web;

public partial class XSSExample : System.Web.UI.Page
{
    string userInput = Request.QueryString["input"];

    protected void Page_Load(object sender, EventArgs e) 
    {
        string userInput = "asdfj";   
        string encodedInput = HttpUtility.HtmlEncode(userInput);        
        Response.Write("<h1>Bem-vindo, " + encodedInput + "</h1>");
    }
} 
  */