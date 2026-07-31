<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Validator;
use App\Services\SafeHavenService;

class AuthController extends Controller
{
    public function register(Request $request, SafeHavenService $safeHavenService)
    {
        $validator = Validator::make($request->all(), [
            'name' => 'required|string|max:255',
            'email' => 'required|string|email|max:255|unique:users',
            'password' => 'required|string|min:6',
            'phone' => 'nullable|string|max:20|unique:users',
        ]);

        if ($validator->fails()) {
            return response()->json(['errors' => $validator->errors()], 422);
        }

        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'phone' => $request->phone,
            'password' => $request->password, // automatically hashed by casts
        ]);

        $token = $user->createToken('auth_token')->plainTextToken;

        // Create Virtual account for user
        $account = $safeHavenService->createAccount($user);


        // Send Welcome Email (logged to storage/logs/laravel.log)

        // QUEUE THIS TO BE SENT IN THE BACKGROUND
        try {
            Mail::raw("Welcome to PayPoint, {$user->name}! Your account has been registered successfully. You can now set your security PIN to start using all PayPoint services.", function ($message) use ($user) {
                $message->to($user->email)
                    ->subject('Welcome to PayPoint!');
            });
        } catch (\Exception $e) {
            // Log error but don't fail registration
            logger()->error('Failed to send welcome email: ' . $e->getMessage());
        }

        return response()->json([
            'user' => [
                'id' => $user->id,
                'name' => $user->name,
                'email' => $user->email,
                'phone' => $user->phone,
                'account' => $account,
                'is_pin_set' => false,
            ],
            'token' => $token,
        ], 201);
    }

    public function login(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'email' => 'required|string|email',
            'password' => 'required|string',
        ]);

        if ($validator->fails()) {
            return response()->json(['errors' => $validator->errors()], 422);
        }

        $user = User::where('email', $request->email)->first();

        if (!$user || !Hash::check($request->password, $user->password)) {
            return response()->json(['message' => 'Invalid login credentials'], 401);
        }

        $token = $user->createToken('auth_token')->plainTextToken;
        $isPinSet = !is_null($user->pin);

        return response()->json([
            'user' => [
                'id' => $user->id,
                'name' => $user->name,
                'email' => $user->email,
                'phone' => $user->phone,
                'is_pin_set' => $isPinSet,
            ],
            'token' => $token,
        ]);
    }

    public function logout(Request $request)
    {
        $request->user()->currentAccessToken()->delete();

        return response()->json([
            'message' => 'Logged out successfully',
        ]);
    }

    public function setPin(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'pin' => 'required|numeric|digits:4',
        ]);

        if ($validator->fails()) {
            return response()->json(['errors' => $validator->errors()], 422);
        }

        $user = $request->user();
        $user->pin = $request->pin; // automatically hashed by casts
        $user->save();

        return response()->json([
            'message' => 'Security PIN updated successfully',
            'is_pin_set' => true,
        ]);
    }

    public function verifyPin(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'pin' => 'required|numeric|digits:4',
        ]);

        if ($validator->fails()) {
            return response()->json(['errors' => $validator->errors()], 422);
        }

        $user = $request->user();

        if (is_null($user->pin)) {
            return response()->json(['message' => 'Security PIN is not set'], 400);
        }

        if (!Hash::check($request->pin, $user->pin)) {
            return response()->json(['message' => 'Incorrect security PIN'], 401);
        }

        return response()->json([
            'message' => 'Security PIN verified successfully',
        ]);
    }

    public function forgotPassword(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'email' => 'required|string',
        ]);

        if ($validator->fails()) {
            return response()->json(['errors' => $validator->errors()], 422);
        }

        $user = User::where('email', $request->email)
            ->first();

        if (!$user) {
            return response()->json(['message' => 'No account found with this details'], 404);
        }

        $code = (string) rand(100000, 999999);
        Cache::put('password_reset_' . $user->id, $code, now()->addMinutes(15));

        // Send reset email
        try {
            Mail::raw("Your PayPoint password reset code is: {$code}. It will expire in 15 minutes.", function ($message) use ($user) {
                $message->to($user->email)
                    ->subject('Password Reset Code');
            });
        } catch (\Exception $e) {
            logger()->error('Failed to send password reset email: ' . $e->getMessage());
        }

        return response()->json([
            'message' => 'Password reset code has been sent',
            'email' => $user->email,
            'code' => $code, // returned for easier mobile client testing
        ]);
    }

    public function verifyResetCode(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'email' => 'required|string',
            'code' => 'required|string',
        ]);

        if ($validator->fails()) {
            return response()->json(['errors' => $validator->errors()], 422);
        }

        $user = User::where('email', $request->email)
            ->first();

        if (!$user) {
            return response()->json(['message' => 'User not found'], 404);
        }

        $cachedCode = Cache::get('password_reset_' . $user->id);

        if (!$cachedCode || $cachedCode !== $request->code) {
            return response()->json(['message' => 'Invalid or expired verification code'], 400);
        }

        return response()->json([
            'message' => 'Code verified successfully',
        ]);
    }

    public function resetPassword(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'email' => 'required|string',
            'code' => 'required|string',
            'password' => 'required|string|min:6',
        ]);

        if ($validator->fails()) {
            return response()->json(['errors' => $validator->errors()], 422);
        }

        $user = User::where('email', $request->email)
            ->first();

        if (!$user) {
            return response()->json(['message' => 'User not found'], 404);
        }

        $cachedCode = Cache::get('password_reset_' . $user->id);

        if (!$cachedCode || $cachedCode !== $request->code) {
            return response()->json(['message' => 'Invalid or expired verification code'], 400);
        }

        $user->password = $request->password; // automatically hashed by casts
        $user->save();

        Cache::forget('password_reset_' . $user->id);

        return response()->json([
            'message' => 'Password reset successfully',
        ]);
    }
}
