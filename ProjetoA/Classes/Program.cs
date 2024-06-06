using MongoDB.Bson;
using MongoDB.Driver;
using System;

class Program
{
    static void Main(string[] args)
    {
        var client = new MongoClient("mongodb://localhost:27017");
        var database = client.GetDatabase("exampleDB"); 
        var collection = database.GetCollection<BsonDocument>("users");  

        Console.Write("Username: ");
        var username = Console.ReadLine();

        Console.Write("Password: ");
        var password = Console.ReadLine();

        var filter = Builders<BsonDocument>.Filter.And(   
            Builders<BsonDocument>.Filter.Eq("username", username), 
            Builders<BsonDocument>.Filter.Eq("password", password)
        ); 
          
        var user = collection.Find(filter).FirstOrDefault() ;           
          
        if (user != null)
        {
            Console.WriteLine("Login successful!");
        }
        else
        { 
            Console.WriteLine("Invalid username or password.");
        }
    }

    static void DoSomeShit(string n)
    {

    }
}