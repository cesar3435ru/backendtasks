<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Validator;
use App\Models\User;

class AuthController extends Controller
{
    public function __construct()
    {
        $this->middleware('auth:api', ['except' => ['login', 'registerUser']]);
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
            'password' => 'nullable|string|min:8' // La contraseña es opcional en la actualización
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
}
