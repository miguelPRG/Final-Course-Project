using Windows.System;
using Windows.UI;

public class UserController : Controller
{
    public IActionResult GetUser(string userId)
    {
        string sqlQuery = "SELECT * FROM Users WHERE UserId = " + userId;
        var user = _context.Users.FromSqlRaw(sqlQuery).ToList();
        return View(user);
    }

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
}