<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class JWTAuthMiddleware
{
    /**
     * Handle an incoming request.
     *
     * @param  \Closure(\Illuminate\Http\Request): (\Symfony\Component\HttpFoundation\Response)  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        $token = $request->header('Authorization');
        $url = $request->fullUrl();

        if(!$token) {
            return $this->unauthorizedResponse($url, $next, $request);
        } else {
            list($header, $payload, $signature) = explode('.', $token);
            $header = json_decode(base64_decode(str_replace(['-', '_'], ['+', '/'], $header)), true);

            if (!isset($header['alg']) || $header['alg'] !== 'HS256') {
                return $this->unauthorizedResponse($url, $next, $request);
            } else {
                $secretKey = getenv('JWT_SECRET');

                if ($secretKey === false) {
                    return $this->unauthorizedResponse($url, $next, $request);
                }

                $valid = hash_equals(
                    str_replace(['-', '_', ''], ['+', '/', '='], base64_encode(hash_hmac('sha256', $header . "." . $payload, $secretKey, true))),
                    $signature
                );

                $payload = json_decode(base64_decode(str_replace(['-', '_'], ['+', '/'], $payload)), true);

                if (isset($payload['exp']) && $payload['exp'] < time()) {
                    return $this->unauthorizedResponse($url, $next, $request);
                }

                if (!$valid || $this->isTokenRevoked($token)) {
                    return $this->unauthorizedResponse($url, $next, $request);
                }
            }
        }

        return $next($request);
    }

    private function unauthorizedResponse($url, $next, $request)
    {
        switch ($url) {
            case getenv('APP_URL') . '/api':
                return response()->json(['error' => 'Authentication failed'], 401);
            default:
                return $next($request);
        }
    }

    private function isTokenRevoked($token)
    {
        // Check if the token is in the list of revoked tokens.
        // This is a placeholder and should be replaced with actual implementation.
        return false;
    }
}
