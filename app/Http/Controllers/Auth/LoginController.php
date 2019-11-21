<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use Authy\AuthyApi;
use Illuminate\Foundation\Auth\AuthenticatesUsers;
use Illuminate\Http\Request;

class LoginController extends Controller
{
    /*
    |--------------------------------------------------------------------------
    | Login Controller
    |--------------------------------------------------------------------------
    |
    | This controller handles authenticating users for the application and
    | redirecting them to your home screen. The controller uses a trait
    | to conveniently provide its functionality to your applications.
    |
     */

    use AuthenticatesUsers;

    /**
     * Where to redirect users after login.
     *
     * @var string
     */
    protected $redirectTo = '/home';

    /**
     * Create a new controller instance.
     *
     * @return void
     */
    public function __construct()
    {
        $this->middleware('guest')->except('logout');
    }

/**
 * The user has been authenticated.
 *
 * @param  \Illuminate\Http\Request  $request
 * @param  mixed  $user
 * @return mixed
 */
    protected function authenticated(Request $request, $user)
    {
        $authy_api = new AuthyApi(env("AUTHY_SECRET"));
        $authy_api->requestSms($user->authy_id);
        \session(['isVerified' => false]);
        return \redirect('verify');
    }
}
