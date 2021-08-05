<?php

namespace App\Repositories\Auth;

use Carbon\Carbon;
use Firebase\JWT\JWT;
use App\Models\UserModel as User;
use CodeIgniter\API\ResponseTrait;
use App\Repositories\Auth\AuthInterface;

class AuthRepository implements AuthInterface 
{
    use ResponseTrait;
    
    const STATUS_ACTIVE = 1;
    const ROLE_USER     = 'USER';
    const ONE_HOURS     = 60 * 60;
    
    public function login(object $request)
    {
        $user = new User;
        $user = $user->where('email', $request->email)->first();
        
        // email not exists
        if (empty($user)) {
            return [
                'status'  => false,
                'message' => 'User not found'
            ];
        }
        
        // status not active
        if ($user->is_active != 1) {
            return [
                'status'  => false,
                'message' => 'User status not active'
            ];
        }
        
        // check password
        if (! password_verify($request->password, $user->password)) {
            return [
                'status'  => false,
                'message' => 'Email or password wrong'
            ];
        }

        return [
            'status'  => true,
            'message' => 'Login success',
            'user'    => [
                'fullname'  => $user->fullname,
                'email'     => $user->email,
                'role'      => $user->role,
                'token'     => [
                    'type'       => 'bearer',
                    'jwt'        => $this->generateTokenJwt($user),
                    'expires_in' => self::ONE_HOURS 
                ]
            ]
        ];
        
    }

    /**
     * register
     *
     * @param object $request
     * @return array $dataRegister
     */
    public function register(object $request)
    {
        $dataRegister = [
            'fullname'   => $request->fullname,
            'password'   => password_hash($request->password, PASSWORD_DEFAULT),
            'is_active'  => self::STATUS_ACTIVE,
            'email'      => $request->email,
            'role'       => self::ROLE_USER,
            'created_at' => Carbon::now('Asia/Jakarta')->format('Y-m-d H:i:s')
        ];
        $user = new User;
        $user->insert($dataRegister);

        unset($dataRegister['password']);

        return $dataRegister;
    }

    /**
     * decode token user
     *
     * @param string $tokenJwt
     * @return array
     */
    public function decodeTokenUser(string $tokenJwt)
    {
        $tokenJwt = str_replace('Bearer ', '', $tokenJwt);
        $decoded  = JWT::decode($tokenJwt, env('KEY_JWT'), array('HS256'));

        $user = new User;
        $user = $user->where('id', $decoded->sub)->first();

        // user not exists
        if (empty($user)) {
            return [
                'status'  => false,
                'message' => 'User not found'
            ];
        }

        return [
            'status' => true,
            'message' => 'Get user',
            'user' => [
                'fullname'   => $user->fullname,
                'is_active'  => $user->is_active,
                'email'      => $user->email,
                'role'       => $user->role,
                'created_at' => $user->created_at
            ]
        ];
    }

    /**
     * generate token jwt
     *
     * @param object $user
     * @return string token jwt
     */
    private function generateTokenJwt(object $user)
    {
        $key = env('KEY_JWT');
        $payload = array(
            'sub'    => $user->id,
            'iss'    => env('app.baseURL'),
            'iat'    => time(),
            'nbf'    => time(),
            'exp'    => time() + self::ONE_HOURS,
            'jti'    => uniqid(),
            'prv'    => sha1(uniqid())
        );

        return JWT::encode($payload, $key);
    }
}