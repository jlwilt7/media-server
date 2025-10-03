<?php
/**
 * User Login API
 * This endpoint handles user authentication (logging in)
 * 
 * How to use:
 * Send a POST request with: username, password
 * Example: POST to /backend/api/auth/login.php
 */

// ============================================
// STEP 1: Start Session
// ============================================
// Sessions let us remember who's logged in across multiple pages

// session_start() initializes PHP sessions
// This creates/loads a session cookie in the browser
session_start();

// ============================================
// STEP 2: Set HTTP Headers
// ============================================
// Same as register.php - tell browser how to handle our response

header("Access-Control-Allow-Origin: *");
header("Content-Type: application/json; charset=UTF-8");
header("Access-Control-Allow-Methods: POST");
header("Access-Control-Max-Age: 3600");
header("Access-Control-Allow-Headers: Content-Type, Access-Control-Allow-Headers, Authorization, X-Requested-With");

// ============================================
// STEP 3: Include Required Files
// ============================================
require_once '../../config/database.php';
require_once '../../includes/functions.php';

// ============================================
// STEP 4: Check Request Method
// ============================================
// Only allow POST requests

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    sendJsonResponse(405, false, 'Method not allowed. Use POST.');
}

// ============================================
// STEP 5: Validate Required Fields
// ============================================
// Make sure username and password were submitted

$validation = validateRequiredFields(['username', 'password']);

if (!$validation['valid']) {
    sendJsonResponse(400, false, 'Missing required fields: ' . implode(', ', $validation['missing']));
}

// ============================================
// STEP 6: Get Input Data
// ============================================
// Get the submitted username and password

// Sanitize username to prevent XSS attacks
$username = sanitizeInput($_POST['username']);

// Don't sanitize password - we need it exactly as typed
$password = $_POST['password'];

// ============================================
// STEP 7: Connect to Database
// ============================================
$database = new Database();
$db = $database->getConnection();

if ($db === null) {
    sendJsonResponse(500, false, 'Database connection failed');
}

// ============================================
// STEP 8: Find User in Database
// ============================================
// Look up the user by username

// SQL query to get user data
// We need the password_hash to verify the password
$query = "SELECT id, username, email, password_hash, is_admin FROM users WHERE username = :username";

$stmt = $db->prepare($query);
$stmt->bindParam(':username', $username);
$stmt->execute();

// ============================================
// STEP 9: Check if User Exists
// ============================================
// If no user found with this username, login fails

if ($stmt->rowCount() === 0) {
    // No user found with this username
    // 401 = Unauthorized
    // We don't specify if username or password is wrong (security best practice)
    sendJsonResponse(401, false, 'Invalid username or password');
}

// ============================================
// STEP 10: Get User Data
// ============================================
// Fetch the user data from the query result

// fetch() returns one row as an associative array
// Example: ['id' => 1, 'username' => 'john', 'email' => 'john@example.com', ...]
$user = $stmt->fetch();

// ============================================
// STEP 11: Verify Password
// ============================================
// Check if the entered password matches the stored hash

// password_verify() is built-in PHP function
// It compares plain-text password with hashed password
// Returns true if they match, false if not
if (!password_verify($password, $user['password_hash'])) {
    // Password doesn't match
    sendJsonResponse(401, false, 'Invalid username or password');
}

// ============================================
// STEP 12: Update Last Login Time
// ============================================
// Record when user last logged in (useful for analytics)

// SQL to update the last_login timestamp
// NOW() is a MySQL function that returns current date/time
$updateQuery = "UPDATE users SET last_login = NOW() WHERE id = :id";
$updateStmt = $db->prepare($updateQuery);
$updateStmt->bindParam(':id', $user['id']);
$updateStmt->execute();

// ============================================
// STEP 13: Create Session
// ============================================
// Store user info in session so they stay logged in

// $_SESSION is a superglobal array that persists across pages
// We store important user info in it

$_SESSION['user_id'] = $user['id'];           // Store user's ID
$_SESSION['username'] = $user['username'];     // Store username
$_SESSION['is_admin'] = $user['is_admin'];     // Store admin status
$_SESSION['logged_in'] = true;                 // Flag to check if logged in

// ============================================
// STEP 14: Send Success Response
// ============================================
// Tell client the login was successful and send user data

// 200 = OK status code (success)
sendJsonResponse(200, true, 'Login successful', [
    'user_id' => $user['id'],
    'username' => $user['username'],
    'email' => $user['email'],
    'is_admin' => $user['is_admin']
]);
?>
