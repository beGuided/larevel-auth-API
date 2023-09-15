<?php
namespace App\Http\Controllers\Api;

use Illuminate\Support\Facades\Auth;

use  App\Models\User;
use Illuminate\Http\Request;
use App\Http\Controllers\Controller;
use Illuminate\Validation\Rule;
use Illuminate\Support\Facades\Hash;
use Illuminate\Auth\Events\Registered;



class AuthController extends Controller
{   

    /**
     * Store a newly created resource in storage.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\Response
     */
    public function register(Request $request)
    {
  
        $formFields = $request->validate([
            'name' => ['required', 'min:3'],
            'email' => ['required', 'email', Rule::unique('users', 'email')],
            'password' => 'required|min:6'
        ]);

        // Hash Password
        $formFields['password'] = bcrypt($formFields['password']);

        $user = User::create($formFields);

        event(new Registered($user));
       $token = $user->createToken('myapptoken')->plainTextToken;
       
        $response = [
            'message' => 'Registration successful. Please check your email for verification link.',
             'user'=> $user, 'token' => $token   ];
        return response($response, 201); 

    }

    // public function verifyEmail(EmailVerificationRequest $request)
    //  {
    //     if ($request->user()->hasVerifiedEmail()) {
    //         return [
    //             'message' => 'Email already verified'
    //         ];
    //     }
    //     $request->fulfill();
    //     return response()->json(['message' => 'Email verified successfully.'], 200);
    // }

    public function verifyEmail($id, $hash)
    {
        $user = User::find($id);
        abort_if(!$user, 405);
        abort_if(!hash_equals($hash, sha1($user->getEmailForVerification())), 405);

        if (!$user->hasVerifiedEmail()) {
            $user->markEmailAsVerified();
            event(new Verified($user));        
            }
            return [   'message' => 'Email verified', 'status'=>true     ];
        
    }
  
      // Show Login Form
      public function login(Request $request) {
        $formFields = $request->validate([
            'email' => ['required', 'email'],
            'password' => 'required|min:6'
        ]);

        // Hash Password
        $user = User::where('email', $formFields['email'])->first();

        if(!$user || !Hash::check($formFields['password'], $user->password)) {
            return response([
                'message' => 'Invalid login creds'
            ], 401);
        }
       $token = $user->createToken('myapptoken')->plainTextToken;
       
        $response = [ 
            'user'=> $formFields, 
            'token' => $token   ];
        return response($response, 201); 
    }



    // Logout User
    public function logout(Request $request) {
       $request->user()->currentAccessToken()->delete();
       
        return [
            'message' => 'Logged out'
        ];
    }
  
    // Authenticate User
   
}
