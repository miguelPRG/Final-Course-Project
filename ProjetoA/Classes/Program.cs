/*using System.Net;

public class LdapController : Controller
{
    private readonly LdapConnection _connection;

    public LdapController(LdapConnection connection)
    {
        _connection = connection;
    }

    [HttpPost]
    public IActionResult Authenticate(string username, string password)
    { 
        var searchFilter = $"(&(objectClass=user)(sAMAccountName={username}))";  
                          
        var searchRequest = new SearchRequest("dc=example,dc=com", searchFilter, SearchScope.Subtree);
        var searchResponse = (SearchResponse)_connection.SendRequest(searchRequest);

        if (searchResponse.Entries.Count > 0)  
        {
            var user = searchResponse.Entries[0];
            var networkCredential = new NetworkCredential(user.DistinguishedName, password);
            _connection.Bind(networkCredential);
            return Ok();
        }

        return Unauthorized();
    }
}*/