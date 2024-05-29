/*using System;
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;

[Serializable]
public class User
{
    public string Name { get; set; }
}

class Program
{
    static void Main() 
    {
        // Dados binários de entrada (potencialmente maliciosos)
        byte[] serializedData = GetSerializedDataFromUntrustedSource();

        // Deserialização insegura
        User user = (User)Deserialize(serializedData);
        Console.WriteLine($"Nome do usuário: {user.Name}");
    }

    static byte[] GetSerializedDataFromUntrustedSource()
    {
        // Simulação de dados binários que poderiam vir de uma fonte não confiável
        // Em um cenário real, isso poderia vir de uma rede, arquivo ou banco de dados.
        using (MemoryStream ms = new MemoryStream())
        {
            BinaryFormatter formatter = new BinaryFormatter();
            formatter.Serialize(ms, new User { Name = "Usuário Malicioso" });
            return ms.ToArray();
        }
    }

    static object Deserialize(byte[] data)
    {
        using (MemoryStream ms = new MemoryStream(data))
        { 
            BinaryFormatter formatter = new BinaryFormatter();   
            return formatter.Deserialize(ms);    // Ponto de vulnerabilidade
        } 
    }    
}
`*/