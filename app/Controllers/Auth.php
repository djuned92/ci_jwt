<?php

namespace App\Controllers;

use Config\Services;
use CodeIgniter\API\ResponseTrait;
use App\Repositories\Auth\AuthRepository;
use CodeIgniter\Commands\Server\Serve;

class Auth extends BaseController
{
    use ResponseTrait;
    
    public $validation;

    public function __construct()
    {
        $this->auth       = new AuthRepository;
        $this->validation = Services::validation();
    }
    
    public function login()
    {
        $this->validation->setRules([
            'password'         => 'required|min_length[8]',
            'email'            => 'required|valid_email'
        ]);

        // check validation
        if ($this->validation->run((array) $this->request->getJSON()) === false) {
            return $this->respond(['errors' => $this->validation->getErrors()]);
        }

        $dataLogin    = $this->auth->login($this->request->getJSON());
        $dataResponse = [
            'status'  => $dataLogin['status'],
            'message' => $dataLogin['message'],
            'data'    => [
                'user' => $dataLogin['user'] ?? (object) []
            ]
        ];
        return $this->respond($dataResponse);
    }

    /**
     * register
     *
     * @param raw data register
     * @return json
     */
    public function register()
    {
        $this->validation->setRules([
            'fullname'         => 'required',
            'password'         => 'required|min_length[8]',
            'password_confirm' => 'required|matches[password]',
            'email'            => 'required|valid_email|is_unique[users.email]'
        ]);

        // check validation
        if ($this->validation->run((array) $this->request->getJSON()) === false) {
            return $this->respond(['errors' => $this->validation->getErrors()]);
        }

        $userRegister = $this->auth->register($this->request->getJSON());
        $dataResponse = [
            'status'  => true,
            'message' => 'Registered successfully',
            'data'    => [
                'user' => $userRegister
            ]
        ];
        return $this->respondCreated($dataResponse);
    }

    /**
     * decode token jwt get user
     *
     * @param header Authorization Bearer {token}
     * @return json
     */
    public function decodeTokenUser()
    {
        $dataUser     = $this->auth->decodeTokenUser($this->request->getHeaderLine('Authorization'));
        $dataResponse = [
            'status'  => $dataUser['status'],
            'message' => $dataUser['message'],
            'data'    => [
                'user' => $dataUser['user'] ?? (object) []
            ]
        ];
        return $this->respond($dataResponse);
    }
}
