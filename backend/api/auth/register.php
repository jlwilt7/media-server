<?php
/**
 * User Registration API
 * This endpoint handles creating new user accounts
 * 
 * How to use:
 * Send a POST request to this file with: username, email, password
 * Example: POST to /backend/api/auth/register.php
 */

// ============================================
// STEP 1: Set HTTP Headers
// ============================================
// Headers tell the browser/client how to interpret our response

// Allow requests from any domain (needed for AJAX requests)
// * means "allow from anywhere"
header("Access-Control-Allow-Origin: *");

// Tell browser we're sending JSON data
header("Content-Type: application/json; charset=UTF-8");

// Tell browser we only accept POST requests (not GET, PUT, DELETE, etc.)
header("Access-Control-Allow-Methods: POST");

// Cache this header response for 1 hour (3600 seconds)
header("Access-Control-Max-Age: 3600");

// Allow these specific headers in the request
header("Access-Control-Allow-Headers: Content-Type, Access-Control-Allow-Headers, Authorization, X-Requested-With");

// ============================================
// STEP 2: Include Required Files
// ============================================
// We need these files to work with database and helper functions

// Go up 2 directories (../..) to reach config folder, then load database.php
require_once '../../config/database.php';

// Go up 2 directories to reach includes folder, then load functions.php
require_once '../../includes/functions.php';

// ============================================
// STEP 3: Check Request Method
// ============================================
// Make sure this is a POST request (not GET, etc.)

// $_SERVER is a superglobal array containing server info
// REQUEST_METHOD tells us if it's GET, POST, PUT, DELETE, etc.
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    // !== means "is NOT exactly equal to"
    // If not POST, send error and stop
    sendJsonResponse(405, false, 'Method not allowed. Use POST.');
}

// ============================================
// STEP 4: Validate Required Fields Exist
// ============================================
// Check if username, email, and password were submitted

// Call our helper function to check if these 3 fields exist
$validation = validateRequiredFields(['username', 'email', 'password']);

// If validation failed (fields are missing)
if (!$validation['valid']) {
    // implode() joins array items with commas: ['a', 'b'] becomes "a, b"
    sendJsonResponse(400, false, 'Missing required fields: ' . implode(', ', $validation['missing']));
}

// ============================================
// STEP 5: Get and Clean Input Data
// ============================================
// Get the submitted data from the POST request

// $_POST is a superglobal array containing all POST data
// We sanitize username and email to remove dangerous characters
$username = sanitizeInput($_POST['username']);
$email = sanitizeInput($_POST['email']);

// DON'T sanitize password - we need it exactly as user typed it
// We'll hash it later, so it's safe
$password = $_POST['password'];

// ============================================
// STEP 6: Validate Username Length
// ============================================
// Username must be between 3 and 50 characters

if (strlen($username) < 3 || strlen($username) > 50) {
    // || means "OR" - if EITHER condition is true
    sendJsonResponse(400, false, 'Username must be between 3 and 50 characters');
}

// ============================================
// STEP 7: Validate Email Format
// ============================================
// Check if email looks valid (has @, domain, etc.)

if (!isValidEmail($email)) {
    // ! means "NOT" - if email is NOT valid
    sendJsonResponse(400, false, 'Invalid email format');
}

// ============================================
// STEP 8: Validate Password Strength
// ============================================
// Check if password meets our security requirements

// Call our password validation function
$passwordValidation = validatePassword($password);

// If password validation failed
if (!$passwordValidation['valid']) {
    // Send back the error message explaining what's wrong
    sendJsonResponse(400, false, $passwordValidation['message']);
}

// ============================================
// STEP 9: Connect to Database
// ============================================
// Create database connection using our Database class

// Create new instance of Database class
$database = new Database();

// Call getConnection() method to get PDO connection
$db = $database->getConnection();

// Check if connection failed
if ($db === null) {
    // === means "is exactly equal to"
    sendJsonResponse(500, false, 'Database connection failed');
}

// ============================================
// STEP 10: Check if Username Already Exists
// ============================================
// We can't have two users with the same username

// SQL query to find users with this username
// :username is a placeholder that we'll fill in safely (prevents SQL injection)
$query = "SELECT id FROM users WHERE username = :username";

// Prepare the SQL query
// prepare() creates a prepared statement - safer than regular queries
$stmt = $db->prepare($query);

// Bind the actual username value to the :username placeholder
// This is how we safely insert user data into SQL queries
$stmt->bindParam(':username', $username);

// Execute (run) the query
$stmt->execute();

// Check if any rows were returned
// rowCount() tells us how many matching users were found
if ($stmt->rowCount() > 0) {
    // Found a user with this username - it's taken!
    // 409 = Conflict status code
    sendJsonResponse(409, false, 'Username already exists');
}

// ============================================
// STEP 11: Check if Email Already Exists
// ============================================
// We can't have two users with the same email

// Same process as above, but checking email instead
$query = "SELECT id FROM users WHERE email = :email";
$stmt = $db->prepare($query);
$stmt->bindParam(':email', $email);
$stmt->execute();

if ($stmt->rowCount() > 0) {
    // Found a user with this email - it's taken!
    sendJsonResponse(409, false, 'Email already registered');
}

// ============================================
// STEP 12: Hash the Password
// ============================================
// Never store passwords in plain text! Always hash them.

// password_hash() is a built-in PHP function that securely hashes passwords
// PASSWORD_BCRYPT is the hashing algorithm (very secure)
// This turns "MyPassword123!" into something like "$2y$10$random..."
$password_hash = password_hash($password, PASSWORD_BCRYPT);

// ============================================
// STEP 13: Determine if User Should Be Admin
// ============================================
// First user to register becomes admin automatically

// Start with assumption that user is NOT admin
$is_admin = false;

// Count how many users exist in the database
$countQuery = "SELECT COUNT(*) as total FROM users";
$countStmt = $db->prepare($countQuery);
$countStmt->execute();

// Get the result
// fetch() retrieves one row from the result
$result = $countStmt->fetch();

// If there are currently 0 users, this is the first user!
if ($result['total'] == 0) {
    $is_admin = true; // Make them admin
}

// ============================================
// STEP 14: Insert New User into Database
// ============================================
// Create the user account in the database

// SQL query to insert a new user
// INSERT INTO specifies the table and columns
// VALUES specifies the data (using placeholders)
$query = "INSERT INTO users (username, email, password_hash, is_admin) 
          VALUES (:username, :email, :password_hash, :is_admin)";

// Prepare the insert statement
$stmt = $db->prepare($query);

// Bind all the values to the placeholders
$stmt->bindParam(':username', $username);
$stmt->bindParam(':email', $email);
$stmt->bindParam(':password_hash', $password_hash);

// PDO::PARAM_BOOL tells PDO this is a boolean (true/false) value
$stmt->bindParam(':is_admin', $is_admin, PDO::PARAM_BOOL);

// ============================================
// STEP 15: Execute Insert and Send Response
// ============================================
// Try to insert the user and respond with success or failure

// Execute the insert query
if ($stmt->execute()) {
    // Success! User was created
    
    // Get the ID that was just created
    // lastInsertId() returns the auto-increment ID from the INSERT
    $user_id = $db->lastInsertId();
    
    // Send success response with user data
    // 201 = Created status code (new resource was created)
    sendJsonResponse(201, true, 'User registered successfully', [
        'user_id' => $user_id,
        'username' => $username,
        'email' => $email,
        'is_admin' => $is_admin
    ]);
} else {
    // Failed to insert user (database error)
    // 500 = Internal Server Error
    sendJsonResponse(500, false, 'Failed to register user');
}
?>
