/*using Windows.System;

public class UserController : Controller
{
    [HttpPost]
    public IActionResult Login(string username, string password)
    {  
        // Authenticate user
        var user = AuthenticateUser(username, password);

        if (user == null)
        {
            return Unauthorized();
        } 
          
        // Sending sensitive user information insecurely
        return Ok(new { Username = user.Username, Password = user.Password });
    }

    private User AuthenticateUser(string username, string password)
    {
        // Logic to authenticate user
    }
}*/