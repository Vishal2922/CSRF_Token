<?php
// 1. Session Start (CRUCIAL for CSRF)
// Trainer requirement-padi CSRF session-la irukkira kaaranathinaal idhu top-la irukkanum.
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// 2. Load Environment Variables from .env file
$envPath = __DIR__ . '/../.env';
if (file_exists($envPath)) {
    $lines = file($envPath, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    foreach ($lines as $line) {
        if (strpos(trim($line), '#') === 0) continue; 
        
        if (strpos($line, '=') !== false) {
            list($name, $value) = explode('=', $line, 2);
            $name = trim($name);
            $value = trim($value);
            
            $_ENV[$name] = $value;
            putenv("$name=$value");
        }
    }
}

// 3. Autoload classes 
spl_autoload_register(function ($class) {
    $paths = ['app/controllers/', 'app/models/', 'app/middleware/', 'app/helpers/', 'app/core/'];
    foreach ($paths as $path) {
        $file = __DIR__ . '/../' . $path . $class . '.php';
        if (file_exists($file)) {
            require_once $file;
            return;
        }
    }
});

// 4. Global Middleware (Runs before Routing) 
$jsonMiddleware = new JsonMiddleware();
$jsonMiddleware->handle();

// 5. Initialize Router 
$router = new Router();

// --- Authentication Routes ---
$router->add('POST', '/api/register', 'AuthController', 'register'); 
$router->add('POST', '/api/login', 'AuthController', 'login');

/**
 * Logout & Refresh logic (Existing)
 */
$router->add('POST', '/api/logout', 'AuthController', 'logout', ['AuthMiddleware']); 
$router->add('POST', '/api/token/refresh', 'AuthController', 'refresh');

// --- Protected Patient Module with CSRF Guard ---

// GET requests - CSRF thevai illai (Read-only)
$router->add('GET', '/api/patients', 'PatientController', 'index', ['AuthMiddleware', 'CsrfMiddleware']); 
$router->add('GET', '/api/patients/{id}', 'PatientController', 'show', ['AuthMiddleware', 'CsrfMiddleware']);

/**
 * State-changing requests - CSRF Guard Active
 * Inga 'CsrfMiddleware' add panniyachu. Idhu JWT check-ukku appuram nadakkum.
 */
$router->add('POST', '/api/patients', 'PatientController', 'store', ['AuthMiddleware', 'CsrfMiddleware']); 
$router->add('PUT', '/api/patients/{id}', 'PatientController', 'update', ['AuthMiddleware', 'CsrfMiddleware']);
$router->add('PATCH', '/api/patients/{id}', 'PatientController', 'patch', ['AuthMiddleware', 'CsrfMiddleware']);
$router->add('DELETE', '/api/patients/{id}', 'PatientController', 'destroy', ['AuthMiddleware', 'CsrfMiddleware']); 

$uri = $_SERVER['REQUEST_URI'];
$method = $_SERVER['REQUEST_METHOD'];

/**
 * Router dispatching logic
 */
$router->dispatch($uri, $method);