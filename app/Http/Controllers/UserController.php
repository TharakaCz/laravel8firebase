<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Session;
use Illuminate\Support\Facades\Validator;
use Kreait\Firebase\Contract\Auth;
use Kreait\Firebase\Contract\Database;

class UserController extends Controller
{
    protected $database;
    protected $auth;
    protected $token;
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
            400);
        }

        try {
            if(!$signInResult = $this->auth->signInWithEmailAndPassword($request->email, $request->password)){
                return response([
                    "status" => false,
                    "message" => "authenticate fail",
                ], 500);
            }

            return response([
                "status" => true,
                "message" => "authenticate success",
                "data" => $signInResult->data()
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

        if(!$this->verifyToken()){
            return response([
                "status"=> false,
                "message" => "Unauthorized"],
                401);
        }

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

    public function getUsers(Request $request)
    {

        if(!$this->verifyToken($request->bearerToken())){
            return response([
                "status" => false,
                "message" => "Unauthorized."
            ], 401);
        }

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

    protected function verifyToken($token){

        if($token == "" || $this->token == null){
            return false;
        }

        try {
            if(!$user = $this->auth->verifyIdToken($token)){
                return false;
            }
            return true;

        }catch (\Exception $ex){
            Log::error($ex->getMessage());
            return false;
        }
    }

    protected function storeCookie($token){

        $fiveMinutes = 300;
        $oneWeek = new \DateInterval('P7D');

        try {
            if (\session()->has('fireCookie')){

                $verifiedSessionCookie = $this->auth->verifySessionCookie(\session()->get('fireCookie'));

                $uid = $verifiedSessionCookie->claims()->get('sub');

                return response([
                    "status" => true,
                    "message" => "authorized",
                    "data" => $this->auth->getUser($uid),
                ], 200);

            }

            $sessionCookieString = $this->auth->createSessionCookie($token, $oneWeek);
            Session::push('fireCookie', $sessionCookieString);
            $verifiedSessionCookie = $this->auth->verifySessionCookie($sessionCookieString);

            $uid = $verifiedSessionCookie->claims()->get('sub');

            return response([
                "status" => true,
                "message" => "authorized",
                "data" => $this->auth->getUser($uid),
            ], 200);



        } catch (\Exception $ex) {
            return response([
                "status" => false,
                "message" => $ex->getMessage(),
            ], 500);
        }
    }

    public function socialLogin(Request $request){
        switch (true){
            case $request->provider == "facebook":
               return $this->provider($request->provider, env('FACEBOOK_ACCESS_TOKEN') , env('FACEBOOK_REDIRECT_URL'));
            case $request->provider == "google":
                break;
            default:
                break;

        }
    }

    protected function provider($provider, $accessToken, $redirectUrl){
        $signInResult = $this->auth->signInWithIdpAccessToken($provider, $accessToken, $redirectUrl, $oauthTokenSecret = null, $linkingIdToken = null);
        return $signInResult;
    }
}
