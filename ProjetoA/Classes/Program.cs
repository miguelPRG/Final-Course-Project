/*using System;
using System.Runtime.InteropServices;
using Microsoft.AspNetCore.Mvc;

namespace VulnerableApp.Controllers 
{
    [ApiController]
    [Route("[controller]")] 
    public class UserController : ControllerBase 
    {
        [HttpGet]
        public IActionResult Get()
        {
            // Fetching all user data
            var users = FetchAllUsers();
            return Ok(users);
        }

        private object FetchAllUsers()
        {
            // Simulated user data fetch
            return new[] { new { Id = 1, Name = "John Doe" } };
        }
    }
}*/