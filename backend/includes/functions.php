<?php
/**
 * Helper Functions
 * These are reusable utility functions we'll use throughout the app
 * Think of these as tools in a toolbox - we can use them whenever we need
 */

/**
 * Validate email format
 * Checks if an email address is valid (has @ symbol, domain, etc.)
 * 
 * @param string $email - The email address to check
 * @return bool - Returns true if valid, false if not
 */
function isValidEmail($email) {
    // filter_var is a built-in PHP function that validates different types of data
    // FILTER_VALIDATE_EMAIL is a constant that tells it to check email format
    // !== false means "if it's NOT false" (i.e., if it's valid)
    return filter_var($email, FILTER_VALIDATE_EMAIL) !== false;
}

/**
 * Validate password strength
 * Checks if password meets our security requirements:
 * - At least 8 characters long
 * - Contains at least 1 uppercase letter (A-Z)
 * - Contains at least 1 lowercase letter (a-z)
 * - Contains at least 1 number (0-9)
 * - Contains at least 1 special character (!@#$%^&*)
 * 
 * @param string $password - The password to validate
 * @return array - Returns array with 'valid' (true/false) and 'message' (explanation)
 */
function validatePassword($password) {
    // Create an empty array to store error messages
    $errors = [];
    
    // Check if password is at least 8 characters long
    // strlen() returns the length of a string
    if (strlen($password) < 8) {
        // If too short, add an error message to the array
        $errors[] = "Password must be at least 8 characters long";
    }
    
    // Check if password has at least one uppercase letter
    // preg_match() checks if a pattern exists in a string
    // '/[A-Z]/' is a regex pattern that means "any uppercase letter from A to Z"
    if (!preg_match('/[A-Z]/', $password)) {
        $errors[] = "Password must contain at least one uppercase letter";
    }
    
    // Check if password has at least one lowercase letter
    // '/[a-z]/' means "any lowercase letter from a to z"
    if (!preg_match('/[a-z]/', $password)) {
        $errors[] = "Password must contain at least one lowercase letter";
    }
    
    // Check if password has at least one number
    // '/[0-9]/' means "any digit from 0 to 9"
    if (!preg_match('/[0-9]/', $password)) {
        $errors[] = "Password must contain at least one number";
    }
    
    // Check if password has at least one special character
    // '/[^A-Za-z0-9]/' means "anything that's NOT a letter or number"
    // The ^ inside brackets means "NOT"
    if (!preg_match('/[^A-Za-z0-9]/', $password)) {
        $errors[] = "Password must contain at least one special character";
    }
    
    // Check if we have any errors
    if (empty($errors)) {
        // No errors = password is valid!
        return ['valid' => true, 'message' => 'Password is valid'];
    } else {
        // We have errors - combine them into one message
        // implode() joins array elements into a string with '. ' between each one
        return ['valid' => false, 'message' => implode('. ', $errors)];
    }
}

/**
 * Sanitize input string
 * Cleans user input to prevent security issues
 * This removes dangerous characters that could be used for hacking
 * 
 * @param string $data - The input data to clean
 * @return string - The cleaned, safe version of the data
 */
function sanitizeInput($data) {
    // Step 1: Remove whitespace from beginning and end
    // trim() removes spaces, tabs, newlines from start and end
    $data = trim($data);
    
    // Step 2: Remove backslashes
    // stripslashes() removes backslashes (\) that might be added by PHP
    $data = stripslashes($data);
    
    // Step 3: Convert special characters to HTML entities
    // htmlspecialchars() converts < > & " ' to safe HTML codes
    // This prevents XSS (Cross-Site Scripting) attacks
    $data = htmlspecialchars($data);
    
    // Return the cleaned data
    return $data;
}

/**
 * Send JSON response
 * This function sends a properly formatted JSON response to the client
 * JSON is a format that both PHP and JavaScript understand
 * 
 * @param int $status - HTTP status code (200 = success, 400 = bad request, 500 = server error)
 * @param bool $success - Was the operation successful? (true or false)
 * @param string $message - Human-readable message to explain what happened
 * @param array $data - Optional additional data to send back (like user info)
 */
function sendJsonResponse($status, $success, $message, $data = null) {
    // Set HTTP response code
    // This tells the browser/app if the request succeeded or failed
    http_response_code($status);
    
    // Set header to tell browser we're sending JSON
    // Content-Type tells the browser what kind of data we're sending
    header('Content-Type: application/json');
    
    // Create an associative array (like a JavaScript object) with our response
    $response = [
        'success' => $success,  // true or false
        'message' => $message   // explanation text
    ];
    
    // If additional data was provided, add it to the response
    // !== null means "if it's not null" (i.e., if something was passed)
    if ($data !== null) {
        $response['data'] = $data;
    }
    
    // Convert PHP array to JSON string and send it
    // json_encode() converts PHP arrays/objects to JSON format
    echo json_encode($response);
    
    // Exit the script - nothing else will run after this
    exit;
}

/**
 * Validate required POST fields
 * Checks if all required form fields were submitted and aren't empty
 * 
 * @param array $required - Array of field names that are required (e.g., ['username', 'email'])
 * @return array - Returns array with 'valid' (true/false) and 'missing' (array of missing field names)
 */
function validateRequiredFields($required) {
    // Create empty array to track which fields are missing
    $missing = [];
    
    // Loop through each required field name
    // foreach is like a "for each item in the array, do this:"
    foreach ($required as $field) {
        // Check if the field wasn't submitted OR if it's empty after trimming whitespace
        // !isset() means "if it doesn't exist"
        // empty(trim()) means "if it's empty after removing spaces"
        if (!isset($_POST[$field]) || empty(trim($_POST[$field]))) {
            // Field is missing or empty - add it to our missing array
            $missing[] = $field;
        }
    }
    
    // Return results
    // 'valid' is true only if missing array is empty (no missing fields)
    // 'missing' contains names of any missing fields
    return [
        'valid' => empty($missing),
        'missing' => $missing
    ];
}
?>
