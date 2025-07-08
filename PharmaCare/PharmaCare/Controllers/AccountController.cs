namespace PharmaCare.Controllers
{
    /* Controller handling user authentication, registration, and profile management */
    public class AccountController : Controller
    {
        private readonly IUserRepository _userRepository;
        private readonly ICategoryRepository _categoryRepository;

        /* Constructor with dependency injection for user and category operations */
        public AccountController(IUserRepository userRepository, ICategoryRepository categoryRepository)
        {
            _userRepository = userRepository;
            _categoryRepository = categoryRepository;
        }

        /* Helper method to load categories into ViewBag for navigation display */
        private void LoadCategories()
        {
            var categories = _categoryRepository.View();
            ViewBag.Categories = categories;
        }

        /* GET: Login page with cache prevention and session validation */
        public IActionResult Login()
        {
            /* Prevent browser caching of login page for security */
            Response.Headers["Cache-Control"] = "no-cache, no-store, must-revalidate";
            Response.Headers["Pragma"] = "no-cache";
            Response.Headers["Expires"] = "0";

            /* Check if user is already logged in and redirect appropriately */
            var userRole = HttpContext.Session.GetString("UserRole");
            if (!string.IsNullOrEmpty(userRole))
            {
                if (userRole == "Admin")
                {
                    return Redirect("/Admin/Index");
                }
                else
                {
                    return Redirect("/FrontEnd/Index");
                }
            }

            Console.WriteLine("GET Login page accessed");

            return View();
        }

        /* POST: Process login form submission with validation and session management */
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(string Email, string Password)
        {
            try
            {
                /* Prevent caching for security */
                Response.Headers["Cache-Control"] = "no-cache, no-store, must-revalidate";
                Response.Headers["Pragma"] = "no-cache";
                Response.Headers["Expires"] = "0";

                /* Basic input validation */
                if (string.IsNullOrEmpty(Email) || string.IsNullOrEmpty(Password))
                {
                    ModelState.AddModelError("", "Email and password are required");
                    return View();
                }

                /* Validate credentials using repository */
                var isValid = await _userRepository.ValidateCredentialsAsync(Email, Password);

                if (isValid)
                {
                    var user = await _userRepository.GetByEmailAsync(Email);
                    if (user != null && user.IsActive)
                    {
                        /* Store user authentication data in session */
                        HttpContext.Session.SetInt32("UserId", user.UserId);
                        HttpContext.Session.SetString("UserName", $"{user.FirstName} {user.LastName}");
                        HttpContext.Session.SetString("UserRole", user.Role);

                        /* Role-based redirection after successful login */
                        string redirectUrl;
                        if (user.Role == "Admin" || user.Role == "Pharmacist")
                        {
                            redirectUrl = "/Admin/Index?loggedIn=true";
                        }
                        else
                        {
                            redirectUrl = "/FrontEnd/Index?loggedIn=true";
                        }
                        return Redirect(redirectUrl);
                    }
                    else if (user != null && !user.IsActive)
                    {
                        ModelState.AddModelError("", "Your account is inactive. Please contact an administrator.");
                        return View();
                    }
                }

                ModelState.AddModelError("", "Invalid email or password");
                return View();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Exception during login: {ex.Message}");
                ModelState.AddModelError("", "An error occurred during login. Please try again.");
                return View();
            }
        }

        /* Logout action with session clearing and cache prevention */
        public IActionResult Logout()
        {
            Response.Headers["Cache-Control"] = "no-cache, no-store, must-revalidate";
            Response.Headers["Pragma"] = "no-cache";
            Response.Headers["Expires"] = "0";

            /* Clear all session data */
            HttpContext.Session.Clear();

            return Redirect("/Account/Login");
        }

        /* GET: Registration form display */
        public IActionResult Register()
        {
            return View();
        }

        /* POST: Process user registration with comprehensive validation */
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(User user, string confirmPassword)
        {
            try
            {
                /* Password confirmation validation */
                if (user.Password != confirmPassword)
                {
                    ModelState.AddModelError("", "Password and confirmation password do not match");
                    return View(user);
                }

                /* Password complexity validation rules */
                if (user.Password.Length < 8)
                {
                    ModelState.AddModelError("Password", "Password must be at least 8 characters long");
                    return View(user);
                }

                if (!user.Password.Any(char.IsUpper))
                {
                    ModelState.AddModelError("Password", "Password must contain at least one uppercase letter");
                    return View(user);
                }

                if (!user.Password.Any(c => !char.IsLetterOrDigit(c)))
                {
                    ModelState.AddModelError("Password", "Password must contain at least one special character");
                    return View(user);
                }

                if (ModelState.IsValid)
                {
                    /* Check for existing email to prevent duplicates */
                    if (await _userRepository.UserExistsAsync(user.Email))
                    {
                        ModelState.AddModelError("Email", "Email already exists");
                        return View(user);
                    }

                    string originalPassword = user.Password;

                    /* Set default role if not specified */
                    if (string.IsNullOrEmpty(user.Role))
                    {
                        user.Role = "User";
                    }

                    var newUser = await _userRepository.CreateAsync(user);

                    if (newUser != null)
                    {
                        /* Verify password hashing worked correctly */
                        var isValid = await _userRepository.ValidateCredentialsAsync(newUser.Email, originalPassword);

                        if (isValid)
                        {
                            /* Auto-login after successful registration */
                            HttpContext.Session.SetInt32("UserId", newUser.UserId);
                            HttpContext.Session.SetString("UserName", $"{newUser.FirstName} {newUser.LastName}");
                            HttpContext.Session.SetString("UserRole", newUser.Role);

                            /* Set success flag for frontend display */
                            TempData["RegistrationSuccess"] = "true";

                            /* Role-based redirection with registration success parameter */
                            if (newUser.Role == "Admin")
                            {
                                return Redirect("/Admin/Index?registered=true");
                            }
                            else
                            {
                                return Redirect("/FrontEnd/Index?registered=true");
                            }
                        }
                        else
                        {
                            TempData["ErrorMessage"] = "Registration completed but automatic login failed. Please try logging in manually.";
                            return Redirect("/Account/Login");
                        }
                    }

                    return Redirect("/Account/Login");
                }
                return View(user);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Registration error: {ex.Message}");
                ModelState.AddModelError("", $"Registration error: {ex.Message}");
                return View(user);
            }
        }

        /* Display user profile information with authentication check */
        public async Task<IActionResult> Profile()
        {
            LoadCategories();

            /* Authentication validation */
            var userId = HttpContext.Session.GetInt32("UserId");
            if (userId == null)
            {
                return Redirect("/Account/Login");
            }

            var user = await _userRepository.GetByIdAsync(userId.Value);
            if (user == null)
            {
                return NotFound();
            }

            return View(user);
        }

        /* GET: Edit profile form with current user data */
        public async Task<IActionResult> EditProfile()
        {
            LoadCategories();

            var userId = HttpContext.Session.GetInt32("UserId");
            if (userId == null)
            {
                return Redirect("/Account/Login");
            }

            var user = await _userRepository.GetByIdAsync(userId.Value);
            if (user == null)
            {
                return NotFound();
            }

            return View(user);
        }

        /* POST: Process profile update with selective field updating */
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> EditProfile(User user)
        {
            try
            {
                LoadCategories();

                if (ModelState.IsValid)
                {
                    var userId = HttpContext.Session.GetInt32("UserId");
                    if (userId == null)
                    {
                        return Redirect("/Account/Login");
                    }

                    var currentUser = await _userRepository.GetByIdAsync(userId.Value);
                    if (currentUser == null)
                    {
                        return NotFound();
                    }

                    /* Update only editable fields to preserve sensitive data */
                    currentUser.FirstName = user.FirstName;
                    currentUser.LastName = user.LastName;
                    currentUser.Email = user.Email;
                    currentUser.PhoneNumber = user.PhoneNumber;
                    currentUser.Address = user.Address;
                    currentUser.City = user.City;

                    var result = await _userRepository.UpdateAsync(currentUser);

                    if (result == null)
                    {
                        TempData["ErrorMessage"] = "Failed to update profile. Please try again.";
                        return View(user);
                    }

                    /* Update session data with new name */
                    HttpContext.Session.SetString("UserName", $"{user.FirstName} {user.LastName}");

                    TempData["SuccessMessage"] = "Profile updated successfully!";
                    return Redirect("/Account/Profile");
                }
                return View(user);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"EditProfile error: {ex.Message}");
                TempData["ErrorMessage"] = "An error occurred while updating your profile. Please try again.";
                return View(user);
            }
        }

        /* GET: Change password form display */
        public IActionResult ChangePassword()
        {
            LoadCategories();

            var userId = HttpContext.Session.GetInt32("UserId");
            if (userId == null)
            {
                return Redirect("/Account/Login");
            }

            return View();
        }

        /* POST: Process password change with current password verification */
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ChangePassword(string currentPassword, string newPassword, string confirmPassword)
        {
            LoadCategories();

            var userId = HttpContext.Session.GetInt32("UserId");
            if (userId == null)
            {
                return Redirect("/Account/Login");
            }

            var user = await _userRepository.GetByIdAsync(userId.Value);
            if (user == null)
            {
                return NotFound();
            }

            /* Verify current password before allowing change */
            var isValid = await _userRepository.ValidateCredentialsAsync(user.Email, currentPassword);
            if (!isValid)
            {
                TempData["ErrorMessage"] = "Current password is incorrect";
                return View();
            }

            /* Force password rehash with special prefix to trigger repository update */
            user.Password = "RESET_PASSWORD_" + newPassword;
            var result = await _userRepository.UpdateAsync(user);

            if (result == null)
            {
                TempData["ErrorMessage"] = "Failed to update password. Please try again.";
                return View();
            }

            TempData["SuccessMessage"] = "Password changed successfully!";
            return Redirect("/Account/Profile");
        }

        /* API endpoint to return categories as JSON for frontend consumption */
        [HttpGet]
        public JsonResult GetCategories()
        {
            var categories = _categoryRepository.View();
            return Json(categories);
        }
    }
}