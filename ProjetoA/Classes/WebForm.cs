using System;
using System.Web;
using System.Xml.Linq;
using Windows.UI.Xaml.Controls;

namespace ProjetoA.Classes
{
    public partial class Default : Page
    {
        protected void Page_Load(object sender, EventArgs e)
        {
            // Suponha que "userInput" seja a entrada do usuário, talvez de um campo de texto em um formulário.
            string userInput = Request.QueryString["input"];

            // Exibe a entrada do usuário sem validação  ou escape na página .
            lblOutput.Text = userInput;
        }
    }
}