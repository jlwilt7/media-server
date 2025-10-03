<?php
/**
 * User Logout API
 * This endpoint handles logging out (destroying the session)
 * 
 * How to use:
 * Send a POST request to /backend/api/auth/logout.php
 */

// ============================================
// STEP 1: Start Session
// ============================================
// We need to start the session to access session variables

session_start();

// ============================================
// STEP 2: Set HTTP Headers
// ============================================
header("Access-Control-Allow-Origin: *");
header("Content-Type: application/json; charset=UTF-8");
header("Access-Control-Allow-Methods: POST");

// ============================================
// STEP 3: Include Functions
// ============================================
require_once '../../includes/functions.php';

// ============================================
// STEP 4: Check Request Method
// ============================================
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    sendJsonResponse(405, false, 'Method not allowed. Use POST.');
}

// ============================================
// STEP 5: Check if User is Logged In
// ============================================
// Make sure there's actually a session to destroy

// Check if 'logged_in' session variable exists and is true
// !isset() means "if it doesn't exist"
if (!isset($_SESSION['logged_in']) || $_SESSION['logged_in'] !== true) {
    // User isn't logged in, so nothing to logout from
    sendJsonResponse(401, false, 'Not logged in');
}

// ============================================
// STEP 6: Destroy Session
// ============================================
// Clear all session data and destroy the session

// Set $_SESSION to an empty array
// This removes all session variables (user_id, username, etc.)
$_SESSION = array();

// session_destroy() completely destroys the session
// This deletes the session file from the server
session_destroy();

// ============================================
// STEP 7: Send Success Response
// ============================================
sendJsonResponse(200, true, 'Logged out successfully');
?>
