using System;
using System.Data.SqlClient;

class Program
{
    static void Main()
    {
        string connectionString = "your_connection_string_here";
        Console.Write("Enter username: ");
        string username = Console.ReadLine();
        Console.Write("Enter password: ");
        string password = Console.ReadLine();

        SqlConnection connection = new SqlConnection(connectionString);
        
            connection.Open();

            // Código vulnerável a SQL Injection
            string query = $"SELECT * FROM Users WHERE Username = '{username}' AND Password = '{password}'";

            using (SqlCommand command = new SqlCommand(query, connection))
            {
                SqlDataReader reader = command.ExecuteReader();
                if (reader.HasRows)
                {
                    Console.WriteLine("Login successful!");
                }
                else
                {
                    Console.WriteLine("Invalid username or password.");
                }
            }
        
    }
}
