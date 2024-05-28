using System;
using System.IO;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Formatters.Binary;

[Serializable]
public class User
{
    public string Name { get; set; }
    public int Age { get; set; }
}

public class Program
{
    public static void Main() 
    {
        // Exemplo de serialização insegura
        byte[] serializedData = GetSerializedDataFromUntrustedSource();
        User user = (User)Deserialize(serializedData);
        Console.WriteLine($"User Name: {user.Name}, Age: {user.Age}");
    }

    // Método que simula a obtenção de dados serializados de uma fonte não confiável
    private static byte[] GetSerializedDataFromUntrustedSource()
    {
        // Em um cenário real, esses dados poderiam vir de um arquivo, rede, etc.
        // Aqui, apenas como exemplo, serializamos um objeto User confiável
        User user = new User { Name = "Alice", Age = 30 };
        IFormatter formatter = new BinaryFormatter();  
        using (MemoryStream stream = new MemoryStream())  
        { 
            formatter.Serialize(stream, user); 
            return stream.ToArray();
        }
    }

    // Método de desserialização insegura 
    private static object Deserialize(byte[] data)  
    {
        IFormatter formatter = new BinaryFormatter(); 
        using (MemoryStream stream = new MemoryStream(data)) 
        { 
            return  formatter.Deserialize(stream);         
        }  
    }
}
