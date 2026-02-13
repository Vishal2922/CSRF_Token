<?php
class AuthController
{
    private $db;

    public function __construct()
    {
        $database = new Database();
        $this->db = $database->getConnection();
    }

    /**
     * 1. REGISTER: Unga original validation logic matum Gmail check apdiye irukku.
     */
    public function register()
    {
        $data = $_POST['body'] ?? json_decode(file_get_contents("php://input"), true);

        if (empty($data['name']) || empty($data['email']) || empty($data['password'])) {
            Response::json(400, "Name, Email and Password are required");
        }

        // Unga specific @gmail.com check
        if (!filter_var($data['email'], FILTER_VALIDATE_EMAIL) || !str_ends_with($data['email'], '@gmail.com')) {
            Response::json(400, "Invalid email. Only @gmail.com addresses are accepted.");
        }

        // Unga strong password regex
        $passwordRegex = '/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/';
        if (!preg_match($passwordRegex, $data['password'])) {
            Response::json(400, "Password weak! Must be >= 8 chars with uppercase, lowercase, number, and special char.");
        }

        $user = new User($this->db);
        $user->name = $data['name'];
        $user->email = $data['email'];

        if ($user->emailExists()) {
            Response::json(400, "Email already exists");
        }

        $user->password = password_hash($data['password'], PASSWORD_DEFAULT);

        if ($user->create()) {
            Response::json(201, "User registered successfully");
        } else {
            Response::json(500, "Unable to register user due to a system error");
        }
    }

    
    public function login()
    {
        $data = $_POST['body'] ?? json_decode(file_get_contents("php://input"), true);

        if (empty($data['email']) || empty($data['password'])) {
            Response::json(400, "Email and Password are required");
        }

        $user = new User($this->db);
        $user->email = $data['email'];

        if ($user->emailExists()) {
            if (password_verify($data['password'], $user->password)) {

                $payload = [
                    "user_id" => $user->id,
                    "email" => $user->email
                ];

                $accessToken = JWT::generateAccessToken($payload);
                $refreshToken = JWT::generateRefreshToken($payload);

                // CSRF Token Generation & Storage in Session
                if (session_status() === PHP_SESSION_NONE) {
                    session_start();
                }
                $csrfToken = bin2hex(random_bytes(32)); //64 chars string
                $_SESSION['csrf_token'] = $csrfToken;

                /**
                 * EXISTING SECURITY: Hashed Refresh Token in DB.
                 */
                if (!$user->updateRefreshToken($user->id, $refreshToken)) {
                    Response::json(500, "Error saving session.");
                }

                setcookie('refresh_token', $refreshToken, [
                    'expires' => time() + (int)$_ENV['JWT_REFRESH_EXPIRY'],
                    'path' => '/',
                    'httponly' => true,
                    'samesite' => 'Strict'
                ]);

                Response::json(200, [
                    "message" => "Login successful",
                    "access_token" => $accessToken,
                    "csrf_token" => $csrfToken, // CSRF sent in JSON body
                    "access_token_expiry" => (int)$_ENV['JWT_ACCESS_EXPIRY'] . " seconds",
                    "refresh_token_validity" => "Session active for 1 day"
                ]);
            } else {
                Response::json(401, "Invalid password");
            }
        } else {
            Response::json(404, "User not found");
        }
    }
    

    // 3. TOKEN REFRESH
    public function refresh()
    {
        // 1. Header Extraction (Expired Access Token)
        $headers = getallheaders();
        $authHeader = $headers['Authorization'] ?? $headers['authorization'] ?? null;
        $currentAccessToken = null;

        if ($authHeader && preg_match('/Bearer\s(\S+)/', $authHeader, $matches)) {
            $currentAccessToken = $matches[1];
        }

        // Access Token illai-naa block
        if (!$currentAccessToken) {
            Response::json(401, "Original Access Token is required.");
            exit();
        }

        // Access Token innum valid-aa irundhaa refresh-ai block pannuvom
        if (JWT::verify($currentAccessToken)) {
            Response::json(403, "Access token is still valid. Manual refresh is forbidden.");
            exit();
        }

        // 2. Cookie Extraction
        $refreshToken = $_COOKIE['refresh_token'] ?? null;
        if (!$refreshToken) {
            Response::json(401, "Refresh token cookie is missing.");
            exit();
        }

        /**
         * IP ADDRESS VALIDATION: (RESTORED)
         * Token-la ulla IP-um current device IP-um match aaganum.
         */
        $refreshData = JWT::verify($refreshToken);
        if (!$refreshData || $refreshData['ip'] !== $_SERVER['REMOTE_ADDR']) {
            Response::json(403, "Security Alert: Device or Network mismatch detected.");
            exit();
        }

        // 3. Payload Extraction from Access Token (Source of Truth)
        $tokenPayload = JWT::getPayload($currentAccessToken);
        if (!$tokenPayload) {
            Response::json(401, "Invalid access token structure.");
            exit();
        }

        $userId = (int)$tokenPayload['user_id'];
        $userModel = new User($this->db);

        /**
                                                 * DB HASH VALIDATION:
         
         */
        $user = $userModel->validateRefreshToken($userId, $refreshToken);

        if ($user) {
            /**
             * PAYLOAD SYNC VALIDATION: (RESTORED)
             */
            if ((int)$user['id'] !== (int)$tokenPayload['user_id'] || $user['email'] !== $tokenPayload['email']) {
                Response::json(403, "Security Alert: Access token payload mismatch with database record.");
                exit();
            }

            // --- All Validations Passed ---

            // 4. Regenerate New Pair (Token Rotation)
            $newAccess = JWT::generateAccessToken(["user_id" => $user['id'], "email" => $user['email']]);
            $newRefresh = JWT::generateRefreshToken(["user_id" => $user['id'], "email" => $user['email']]);

            // DB Update with new Hash
            $userModel->updateRefreshToken($user['id'], $newRefresh);

            setcookie('refresh_token', $newRefresh, [
                'expires' => time() + (int)$_ENV['JWT_REFRESH_EXPIRY'],
                'path' => '/',
                'httponly' => true,
                'samesite' => 'Strict'
            ]);

            // 5. Send Response
            Response::json(200, [
                "access_token" => $newAccess,
                "expires_in" => (int)$_ENV['JWT_ACCESS_EXPIRY']
            ]);
        } else {
            Response::json(401, "Invalid session: Token mismatch or not found in DB.");
        }
    }
    /**
     * 4. LOGOUT: User logic cleanup.
     */
    public function logout()
    {
        $userId = AuthMiddleware::$currentUserId;

        if ($userId) {
            $user = new User($this->db);
            $user->clearRefreshToken($userId);
        }

        setcookie('refresh_token', '', [
            'expires' => time() - 3600,
            'path' => '/',
            'httponly' => true,
            'samesite' => 'Strict'
        ]);

        Response::json(200, ["message" => "Logged out successfully"]);
    }
}
