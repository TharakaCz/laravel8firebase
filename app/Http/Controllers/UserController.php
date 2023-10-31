<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Kreait\Firebase\Contract\Auth;
use Kreait\Firebase\Contract\Database;

class UserController extends Controller
{
    protected $database;
    protected $auth;
    public function __construct(Database $database, Auth $auth)
    {
        $this->database = $database;
        $this->auth = $auth;
    }

    public function auth(Request $request){

        $ruls = Validator::make($request->all(), [
            "email" => ["required", "email"],
            "password" => ["required", "string"]
        ]);

        if ($ruls->fails()){
            return response([
                "status" => false,
                "message" => "Validation fail",
                "errors" => $ruls->errors(),
            ],
            401);
        }

        try {
            if(!$this->auth->signInWithEmailAndPassword($request->email, $request->password)){
                return response([
                    "status" => false,
                    "message" => "authenticate fail",
                ], 500);
            }

            return response([
                "status" => true,
                "message" => "authenticate success",
                "data" => $this->auth
            ], 200);

        }catch (\Exception $ex){
            return response([
                "status" => false,
                "message" => $ex->getMessage(),
            ], 500);
        }

    }

    public function register(Request $request){

        $ruls = Validator::make($request->all(), [
            "email" => ["required", "email"],
            "password" => ["required", "string"]
        ]);

        if ($ruls->fails()){
            return response([
                "status" => false,
                "message" => "Validation fail",
                "errors" => $ruls->errors(),
            ],
                401);
        }

        try {
            if(!$this->auth->createUserWithEmailAndPassword($request->email, $request->password)){
                return response([
                    "status" => false,
                    "message" => "authenticate fail",
                ], 500);
            }

            return response([
                "status" => true,
                "message" => "authenticate success",
            ], 200);
        }catch (\Exception $ex){
            return response([
                "status" => false,
                "message" => $ex->getMessage(),
            ], 500);
        }

    }

    public function create(Request $request){

        $ruls = Validator::make($request->all(), [
            "name" => ["required", "string"],
            "email" => ["required", "email"],
            "password" => ["required", "min:8"],
            "confirm_password" => ["required", "same:password", "min:8"]
        ]);

        if($ruls->fails()){
            return response([
                "status" => false,
                "message" => "Validation fails",
                "errors" => $ruls->errors(),
            ],401);
        }

        $data = [
            "name" => $request->name,
            "email" => $request->email,
            "password" => Hash::make($request->password),
        ];

        try {
            if(!$this->database->getReference('users')->push($data)){
                return response([
                    "status" => false, "message" => "save fail"
                ], 500);
            }

            return response([
                "status" => true, "message" => "successfully save."
            ],200);
        }catch (\Exception $ex){
            return response([
                "status" => true,
                "message" => $ex->getMessage(),
            ],500);
        }
    }

    public function getUsers()
    {
        $response = $this->database->getReference('users')->getValue();

        try {
            if(!$response){
                return response([
                    "status" => false, "message" => "fetching fail"
                ], 500);
            }

            return response([
                "status" => true, "message" => "users list successfully retrieved", "data" => $response
            ], 200);
        }catch (\Exception $ex){
            return response([
                "status" => false,
                "message" => $ex->getMessage(),
            ], 500);
        }
    }

    public function signInAnonymously(Request $request){

        try {
            if (!$response = $this->auth->signInAnonymously()){
                return response([
                    "status" => false,
                    "message" => "authenticate fail",
                ], 500);
            }

            return response([
                "status" => true,
                "message" => "authenticate success",
            ], 500);

        }catch (\Exception $ex){
            return response([
                "status" => false,
                "message" => $ex->getMessage(),
            ], 500);
        }
    }
}
