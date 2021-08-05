<?php

namespace App\Repositories\Auth;

interface AuthInterface 
{
    public function login(object $request);

    public function register(object $request);

    public function decodeTokenUser(string $tokenJwt);
}