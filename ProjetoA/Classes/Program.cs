/*using System;
using System.Data.SqlClient;
using System.Web.UI;
using Windows.UI.Xaml.Controls;

public partial class Login : Page
{
    protected void Page_Load(object sender, EventArgs e)
    {
    }

    protected void btnLogin_Click(object sender, EventArgs e)
    {
        string username = txtUsername.Text;
        string password = txtPassword.Text; 

        // Conexão ao banco de dados
        string connectionString = "your_connection_string_here";
        using (SqlConnection connection = new SqlConnection(connectionString))
        {
            // Consulta SQL vulnerável   
            string query = "SELECT * FROM Users WHERE Username = '" + username  + "' AND Password = '" + password + "'";
             
            SqlCommand command = new SqlCommand(query, connection);  
            connection.Open();
            SqlDataReader reader = command.ExecuteReader();

            if (reader.HasRows)
            {
                // Login bem-sucedido
                lblMessage.Text = "Login successful!";
            }
            else
            {
                // Falha no login
                lblMessage.Text = "Login failed. Invalid username or password.";
            }

            reader.Close();
        }
    }
}
*/