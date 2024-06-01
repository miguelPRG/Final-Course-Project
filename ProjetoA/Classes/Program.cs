/*using System.Web.Mvc;
using Windows.System;
using Windows.UI.Xaml.Controls;

public class AccountController : Controller
{
    [HttpGet]
    public ActionResult ChangePassword()
    {
        return View();
    }
     
    [HttpPost]
    [ValidateAntiForgeryToken]
    public ActionResult ChangePassword(string newPassword)
    {
        var user = GetUserFromSession();
        user.Password = newPassword;
        SaveUser(user);

        ViewBag.Message = "Password changed successfully!";
        return View();
    }

    private User GetUserFromSession()
    {
        return new User { Id = 1, Username = "exampleUser", Password = "oldPassword" };
    }

    private void SaveUser(User user)
    {
        // Simulação de salvar o usuário no banco de dados
    }
}
*/