<?php

/**
 * CsrfMiddleware
 * Handles CSRF validation using Double Submit Cookie Pattern via Sessions.
 */
class CsrfMiddleware
{
    public static function handle()
    {
        // 1. Only validate state-changing methods (As per Roadmap)
        $method = $_SERVER['REQUEST_METHOD'];
        $protectedMethods = ['POST', 'PUT', 'PATCH', 'DELETE'];

        if (in_array($method, $protectedMethods)) {
            
            // 2. Ensure session is active to read the stored token
            if (session_status() === PHP_SESSION_NONE) {
                session_start();
            }

            // 3. Extraction: Get CSRF from Header
            $headers = getallheaders();
            $headerCsrf = $headers['X-CSRF-TOKEN'] ?? $headers['x-csrf-token'] ?? null;
            
            // 4. Extraction: Get CSRF from Session (Stored during Login)
            $sessionCsrf = $_SESSION['csrf_token'] ?? null;

            /**
             * VERIFICATION LOGIC:
             * Failure cases: Header missing, Session expired, or Value mismatch.
             */
            if (!$headerCsrf) {
                Response::json(403, "CSRF token missing in request header.");
                exit();
            }

            if (!$sessionCsrf) {
                Response::json(403, "CSRF session expired or invalid. Please login again.");
                exit();
            }

            if ($headerCsrf !== $sessionCsrf) {
                Response::json(403, "Security Alert: CSRF token mismatch.");
                exit();
            }
        }

        // If GET or Validation Success, continue to Controller
        return true;
    }
}