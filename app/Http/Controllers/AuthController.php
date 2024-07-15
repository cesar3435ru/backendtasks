<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Validator;
use App\Models\User;
use Illuminate\Support\Facades\DB;
use Tymon\JWTAuth\Exceptions\JWTException;
use Tymon\JWTAuth\Exceptions\TokenExpiredException;
use Tymon\JWTAuth\Exceptions\TokenInvalidException;
use Tymon\JWTAuth\Facades\JWTAuth;


class AuthController extends Controller
{
    public function __construct()
    {
        $this->middleware('auth:api', ['except' => ['login', 'registerUser', 'checkEmail', 'resetPassword', 'checkToken','users']]);
    }

    public function registerUser(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'name' => 'required|string|max:40',
            'lastname' => 'required|string|max:60',
            'age' => 'required|integer|between:18,40',
            'email' => 'required|string|email|max:100|unique:users',
            'password' => 'required|string|min:10',
        ]);
        if ($validator->fails()) {
            return response()->json($validator->errors()->toJson(), 400);
        }

        $user = User::create(array_merge(
            $validator->validate(),
            ['password' => bcrypt($request->password)]
        ));

        return response()->json([
            'message' => '¡User created successfully!',
            'user' => $user
        ], 201);
    }

    public function updateUser(Request $request)
    {
        if (!Auth::check()) {
            return response()->json(['error' => 'No access'], 401);
        }

        $user = Auth::user();

        $validator = Validator::make($request->all(), [
            'name' => 'required|string|max:40',
            'lastname' => 'required|string|max:60',
            'age' => 'required|integer|between:18,40',
            'email' => 'required|string|email|unique:users,email,' . $user->id,
            'password' => 'nullable|string|min:8' // The password is optional
        ]);

        if ($validator->fails()) {
            return response()->json(['errors' => $validator->errors()], 422);
        }

        $user->update([
            'name' => $request->name,
            'id' => $user->id, // Assign the user id automatically
            'lastname' => $request->lastname,
            'age' => $request->age,
            'email' => $request->email,
            'password' => $request->password ? bcrypt($request->password) : $user->password // Actualiza la contraseña solo si se proporciona
        ]);

        return response()->json(['user' => $user], 200);
    }

    public function login()
    {
        $credentials = request(['email', 'password']);

        if (!$token = auth()->attempt($credentials)) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }
        $user = auth()->user(); // I get the authenticated user

        return $this->respondWithToken($token, $user);
    }

    public function userProfileInfo()
    {
        return response()->json(auth()->user());
    }

    public function logout()
    {
        auth()->logout();

        return response()->json(['message' => 'Successfully logged out']);
    }

    public function refresh()
    {
        return $this->respondWithToken(auth()->refresh());
    }

    protected function respondWithToken($token, $user)
    {
        return response()->json([
            'access_token' => $token,
            'token_type' => 'bearer',
            'user' => $user,
            'expires_in' => auth()->factory()->getTTL() * 60
        ]);
    }


    public function checkEmail(Request $request)
    {
        // Validate the email input
        $validator = Validator::make($request->all(), [
            'email' => 'required|email',
        ]);

        // Return info when there is an error
        if ($validator->fails()) {
            return response()->json(['error' => $validator->errors()->first()], 400);
        }

        $email = $request->input('email');

        $existingToken = DB::table('password_reset_tokens')->where('email', $email)->first();

        if ($existingToken) {
            return response()->json(['error' => 'Token already generated'], 400);
        }

        // Verify if email exists
        $user = User::where('email', $email)->first();

        if (!$user) {
            return response()->json(['error' => 'Email not found'], 401);
        }

        try {
            // Generate a JWT token for user
            $token = JWTAuth::fromUser($user);

            // Save data in 'password_reset_tokens'
            DB::table('password_reset_tokens')->updateOrInsert(
                ['email' => $email],
                ['token' => $token, 'created_at' => now()]
            );
            return response()->json(['message' => 'JWT has been generated', 'token' => $token], 200);
        } catch (JWTException $e) {
            return response()->json(['error' => 'Error to generate JWT'], 500);
        }
    }



    public function resetPassword(Request $request)
    {
        // Validate the password input
        $validator = Validator::make($request->all(), [
            'new_password' => 'required|string|min:10',
        ]);

        // Return info when there is an error
        if ($validator->fails()) {
            return response()->json(['error' => $validator->errors()->first()], 400);
        }

        $newPassword = $request->input('new_password'); // I get the new password input

        //I get the token as a HTTP Headers
        $token = $request->bearerToken();

        if (!$token) {
            return response()->json(['error' => 'Token not provided'], 401);
        }

        //Verify if token is valid.
        try {
            $user = JWTAuth::parseToken()->authenticate();

            //Verify if both tokens are equal
            $storedToken = DB::table('password_reset_tokens')->where('email', $user->email)->value('token');

            if ($storedToken !== $token) {
                return response()->json(['error' => 'Invalid token'], 401);
            }

            // Update the new password
            $user->update(['password' => bcrypt($newPassword)]);

            auth()->logout();

            //Delete token in the table when action is executed
            DB::table('password_reset_tokens')->where('email', $user->email)->delete();

            return response()->json(['message' => 'Password has been reset successfully'], 200);
        } catch (TokenExpiredException $e) {
            return response()->json(['error' => 'Expired token'], 401);
        } catch (TokenInvalidException $e) {
            return response()->json(['error' => 'Invalid token'], 401);
        } catch (\Exception $e) {
            return response()->json(['error' => 'Error to reset password'], 500);
        }
    }




    public function checkToken(Request $request)
    {
        //I get the token as a HTTP Headers
        $token = $request->bearerToken();

        $tokenData = DB::table('password_reset_tokens')->where('token', $token)->first();

        if (!$tokenData) {
            return response()->json(['error' => 'Token no encontrado'], 401);
        }

        try {
            $user = JWTAuth::parseToken()->authenticate();

            return response()->json(['message' => 'Valid token', 'user' => $user], 200);
        } catch (TokenExpiredException $e) {
            return response()->json(['error' => 'Expired token'], 401);
        } catch (TokenInvalidException $e) {
            return response()->json(['error' => 'Invalid token'], 401);
        } catch (\Exception $e) {
            return response()->json(['error' => 'Error to verify token'], 500);
        }
    }

    public function getUsers(){
        return User::all();
    }
}
