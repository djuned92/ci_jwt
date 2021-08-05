<?php

namespace App\Models;

use CodeIgniter\Model;

class UserModel extends Model
{
    protected $table         = 'users';
    
    protected $primaryKey    = 'id';
    
    protected $allowedFields = [
        'fullname', 'email', 'password', 'is_active', 'email', 'role'
    ];
    
    protected $useTimestamps = true;
    
    protected $returnType    = 'object';
}