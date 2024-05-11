<?php

namespace App\Auth;

use App\Exceptions\InvalidSignatureException;
use App\Exceptions\InvalidTokenException;
use App\Exceptions\MissingSecretKeyException;
use App\Exceptions\TokenExpiredException;
use App\Models\User;
use Illuminate\Support\Facades\Facade;
use Illuminate\Support\Facades\Hash;

class JWTAuth
{
    public static function attempt($credentials)
    {
        $user = User::where('email', $credentials['email'])->first();

        if (! $user || ! Hash::check($credentials['password'], $user->password)) {
            return false;
        }

        return self::fromUser($user);
    }

    public static function fromUser($user)
    {

        $header = json_encode(['typ' => 'JWT', 'alg' => 'HS256']);

        $payload = [
            'iss' => "your-app",
            'sub' => $user->id,
            'iat' => time(),
            'exp' => time() + 60 * 60
        ];

        $payload = json_encode($payload);

        $base64UrlHeader = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($header));
        $base64UrlPayload = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($payload));

        $secretKey = getenv('JWT_SECRET');
        if ($secretKey === false) {
            throw new MissingSecretKeyException('JWT_SECRET is not defined');
        }

        $signature = hash_hmac('sha256', $base64UrlHeader . "." . $base64UrlPayload, $secretKey, true);
        $base64UrlSignature = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($signature));

        $jwt = $base64UrlHeader . "." . $base64UrlPayload . "." . $base64UrlSignature;

        return $jwt;
    }

    public static function verifyToken($token)
    {
        $parts = explode('.', $token);

        if (count($parts) !== 3) {
            throw new InvalidTokenException('Invalid token structure');
        }


        list($base64UrlHeader, $base64UrlPayload, $base64UrlSignature) = $parts;

        $header = json_decode(base64_decode(str_replace(['-', '_', ''], ['+', '/', '='], $base64UrlHeader)), true);
        $payload = json_decode(base64_decode(str_replace(['-', '_', ''], ['+', '/', '='], $base64UrlPayload)), true);

        $secretKey = getenv('JWT_SECRET');

        if ($secretKey === false) {
            throw new MissingSecretKeyException('JWT_SECRET is not defined');
        }

        $signature = hash_hmac('sha256', $base64UrlHeader . "." . $base64UrlPayload, $secretKey, true);
        $base64UrlCheckSignature = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($signature));

        if ($base64UrlSignature !== $base64UrlCheckSignature) {
            throw new InvalidSignatureException('Invalid signature');

        }

        if ($payload['exp'] < time()) {
            throw new TokenExpiredException('Token has expired');
        }

        return $payload;
    }

}

