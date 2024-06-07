using System;
using Microsoft.AspNetCore.Mvc;
using Windows.UI.Xaml.Controls;

namespace VulnerableApp.Controllers
{
    public class HomeController : Controller
    {
        [HttpPost]
        public IActionResult Index(string userInput)
        {
            ViewBag.UserInput = userInput;   
            return View();
        }
    }
}