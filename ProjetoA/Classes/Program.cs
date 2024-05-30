using System;
using System.Data.SqlClient;

class Program
{
    int g; 

    static void Main(string[] args) 
    {
        int g; 

        // Simulação de entrada do usuário 
        Console.WriteLine("Digite o nome do usuário:");
        string nomeUsuario = Console.ReadLine();

        // Conexão com o banco de dados (apenas para fins de exemplo)
        string connectionString = "Data Source=seuserver;Initial Catalog=suabasededados;Integrated Security=True";
        SqlConnection connection = new SqlConnection(connectionString);
         
        // Comando SQL vulnerável 
        string query = "SELECT * FROM Usuarios WHERE Nome = '" + nomeUsuario + "'";  
           
        try
        {    
            connection.Open();   
            SqlCommand command = new SqlCommand(query, connection);    
            SqlDataReader reader = command.ExecuteReader();

            while (reader.Read()) 
            {
                Console.WriteLine("ID: " + reader["ID"] + ", Nome: " + reader["Nome"]);
            }

            reader.Close();
        }
        catch (Exception ex)
        {
            Console.WriteLine("Erro: " + ex.Message);
        }
        finally
        {
            connection.Close();
        }

        Console.ReadLine();
    }
}