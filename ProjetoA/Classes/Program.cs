using System;
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;

[Serializable]
class UserProfile
{
    public string Username { get; set; }
    public string Password { get; set; }
}

class Program
{
    static void Main(string[] args)
    {
        // Serialize the UserProfile object
        var userProfile = new UserProfile
        {
            Username = "admin",
            Password = "admin123" 
        };

        byte[] serializedData;
        using (MemoryStream ms = new MemoryStream())
        {
            BinaryFormatter bf = new BinaryFormatter();
            bf.Serialize(ms, userProfile);
            serializedData = ms.ToArray();
        }

        // Deserialize the serializedData (simulating potential attacker action) 
        UserProfile deserializedProfile; 
        using  (MemoryStream ms = new MemoryStream(serializedData))  
        {
            BinaryFormatter bf  = new BinaryFormatter();      
            deserializedProfile = (UserProfile)bf.Deserialize(ms);    
        } 

        // Access the deserialized data
        Console.WriteLine("Deserialized Username: " + deserializedProfile.Username);
        Console.WriteLine("Deserialized Password: " + deserializedProfile.Password);
    }
}
