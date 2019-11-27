## Securing a Laravel Application with 2FA using Twilio Authy

In this tutorial, you will learn how to secure your Laravel application with [Two-factor authentication](https://authy.com/what-is-2fa/) using [Twilio Authy](https://www.twilio.com/authy).

## Prerequisite
Completing this tutorial will require the following:
- Basic knowledge of Laravel
- [Laravel](https://laravel.com/docs/master) Installed on your local machine
- [Composer](https://getcomposer.org/) globally installed
- [Twilio Account](https://www.twilio.com/referral/B2YAW1)

## Getting Started

Create a new Laravel project using the [Laravel Installer](https://laravel.com/docs/6.x#installation). If you don’t have it installed or prefer to use [Composer](https://laravel.com/docs/6.x/installation), you can check out how to do so from the [Laravel documentation](https://laravel.com/docs/master). Run the following command in your terminal to generate a fresh Laravel project:

    $ laravel new twilio-authy

Next, you will need to set up a database for the application. For this tutorial, we will make use of [MySQL](https://www.mysql.com/) database. If you make use of a database administrator like [phpMyAdmin](https://www.phpmyadmin.net/) for managing your databases then go ahead and create a database named `twilio-authy` and skip this section. If not, install MySQL from the [official site](https://www.mysql.com/downloads/) for your platform of choice. After successful installation, fire up your terminal and run this command to login to MySQL:

    $ mysql -u {your_user_name}

***NOTE:** Add the `-p` flag if you have a password for your MySQL instance.*

Once you are logged in, run the following command to create a new database:

    mysql> create database twilio-authy;
    mysql> exit;

Next, update your `.env` file with your database credentials. Open up `.env` and make the following adjustments:

    DB_DATABASE=twilio-authy
    DB_USERNAME={your_user_name}
    DB_PASSWORD={password if any}

### Setting up Authy
Next, install the Twilio Authy SDK which will be used for sending out Two-factor authentication (2FA) one time passwords:

    $ composer require authy/php

To make use of the Authy SDK you will need to create an Authy service. Head over to your [Twilio console](https://www.twilio.com/console/authy/applications) to create a new Authy service. 

![](https://paper-attachments.dropbox.com/s_6F92FFF40857F8C93B245E0376030C468108DC8801EFBCB45D38A00BB0096318_1574371811327_Group+11.png)

Copy your `PRODUCTION API KEY` from the settings page of your service:

![](https://paper-attachments.dropbox.com/s_6F92FFF40857F8C93B245E0376030C468108DC8801EFBCB45D38A00BB0096318_1574371824818_Group+10+1.png)

Finally, update your `.env` file with the Authy secret:

    AUTHY_SECRET={your_authy_api_key}

## Building Authentication Logic

Out-of-the-box, Laravel allows us to easily scaffold a basic authentication system for both registering and logging-in to your application.

We will be making use of the Laravel `auth` command to scaffold our basic authentication logic. Adjustments will be made later to add two-factor authentication(2fa) to our authentication process. Fire up a terminal in the project directory and run the following command to scaffold a basic authentication system:

    $ php artisan make:auth 

The above command will create the login, registration, and home views, as well as routes for all authentication.

### Updating User Model

With the authentication system scaffolded, let’s begin making adjustments as needed. We need to update the `Users` [migration](https://laravel.com/docs/6.x/migrations) to include new fields for storing `phone_number` and `authy_id`. Open up `database/migrations/2014_10_12_000000_create_users_table.php` and make the following changes to the `up()` method:
    
     /**
         * Run the migrations.
         *
         * @return void
         */
        public function up()
        {
            Schema::create('users', function (Blueprint $table) {
                $table->bigIncrements('id');
                $table->string('name');
                $table->string('email')->unique();
                $table->timestamp('email_verified_at')->nullable();
                $table->string('password');
                $table->string('phone_number');
                $table->string('authy_id');
                $table->rememberToken();
                $table->timestamps();
            });
        }

Next, update the [$fillable](https://laravel.com/docs/6.x/eloquent#mass-assignment) property of the User [model](https://laravel.com/docs/6.x/eloquent). Open up `app/User.php` and make the following adjustment to the `$fillable` array:

    /**
         * The attributes that are mass assignable.
         *
         * @var array
         */
        protected $fillable = [
            'name', 'email', 'password', 'phone_number', 'authy_id',
        ];
    

Now run the following command to execute the migration:

    $ php artisan migrate

This command will create a `users` table in your database with the fields in the `up()` method of the User’s migration file.


## Adding 2FA to Authentication System

At this point, you should have the basic Laravel auth scaffolded. Now let’s make the needed adjustment to add Authy 2FA to our application. First, you will make an adjustment to the `create()` method which is called after successful validation of the data retrieved from the form. Open up the _RegisterController_ (`app/Http/Controllers/Auth/RegisterController.php`) and update the `create()` method as follows:

      /**
         * Create a new user instance after a valid registration.
         *
         * @param  array  $data
         * @return \App\User
         */
        protected function create(array $data)
        {
            $authy_api = new AuthyApi(getenv("AUTHY_SECRET"));
            $authy_user = $authy_api->registerUser($data['email'], $data['phone_number'], $data['country_code']);
            return User::create([
                'name' => $data['name'],
                'email' => $data['email'],
                'password' => Hash::make($data['password']),
                'phone_number' => $data['phone_number'],
                'authy_id' => $authy_user->id(),
            ]);
        }

Let’s break down what is happening here. First you have to initialize the Authy SDK using your `AUTHY_SECRET` stored in your `.env`.To make use of Authy in your application a user must first be registered with the Authy service. This is done using the  inbuilt `registerUser()` method of the Authy SDK:

    $authy_user = $authy_api->registerUser($data['email'], $data['phone_number'], $data['country_code']);

The `registerUser()` method accepts three arguments for the user, `email`, `phone number`, and `country code`. Successful registration will return an `id` to be used for verifying the user’s identity. 

***NOTE:***

- *The `id` returned after registering a user with an Authy service must be stored as part of your user data as this is the only way to identify this user within the Authy service.*
- *You need to update the validation rules in the `validator()` method to include the `phone_number` and `country_code` fields.*

After successful registration of the user with your Authy service, the user data along with the `authy_id` is stored in your *Users* table.

### Sending 2FA OTP
To send out the 2FA OTP to a user, you will have to make changes to what happens after a user has been successfully authenticated. Since we are using the Laravel Auth scaffold we won’t be writing out the entire Login logic, but instead we will make changes to the [authenticated()](https://github.com/laravel/framework/blob/6.x/src/Illuminate/Foundation/Auth/AuthenticatesUsers.php#L120) method of the [AuthenticatesUsers](https://laravel.com/api/6.x/Illuminate/Foundation/Auth/AuthenticatesUsers.html) [trait](https://www.php.net/manual/en/language.oop5.traits.php). To make the needed adjustments, open up `app/Http/Controllers/Auth/LoginController.php` and add the following method:

    /**
     * The user has been authenticated.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  mixed  $user
     * @return mixed
     */
        protected function authenticated(Request $request, $user)
        {
            $authy_api = new AuthyApi(getenv("AUTHY_SECRET"));
            $authy_api->requestSms($user->authy_id);
            \session(['isVerified' => false]);
            return \redirect('verify');
        }

***NOTE:** The `authenticated()` method in the LoginController will override the default Trait’s method because it makes `use` of the AuthenticatesUsers trait.*

Just like before, initialize the Authy SDK with your `AUTHY_SECRET`. Next, request that an SMS OTP should be sent to the user using the `requestSms()` method from the Authy SDK. The `requestSms()` method takes in an argument of the user’s `authy_id` (which we got earlier after successful registration of the user) and sends the user of the `id` an SMS with an OTP code. This code will later be verified before granting the user full access to the dashboard.

Next, we set a [session](https://www.php.net/manual/en/intro.session.php) variable (`isVerified`) to `false` which is used to indicate if the user has been verified using the OTP sent to them via SMS. After successfully sending out the OTP and resetting the `isVerified` flag, you can then redirect the user to a page where he/she will be asked to input the OTP sent to them.

***NOTE:** Apart from the `requestSMS()` method, Twilio Authy SDK also supports other [channels](https://www.twilio.com/docs/authy/two-factor-authentication-channels) for sending the OTP to a user.*

### Verifying 2FA OTP
Next, let’s write out the logic for verifying a user’s OTP code. First generate a [controller](https://laravel.com/docs/6.x/controllers) which will house the logic for verification. Open a terminal and run the following:

    $ php artisan make:controller VerifyController

Now, open the just created file (`app/Http/Controllers/VerifyController.php`) and make the following adjustments:

    <?php
    namespace App\Http\Controllers;
    use Authy\AuthyApi;
    use Illuminate\Http\Request;
    class VerifyController extends Controller
    {
        public function index()
        {
            return view('auth.verify');
        }
        public function verify(Request $request)
        {
            try {
                $data = $request->validate([
                    'verification_code' => ['required', 'numeric'],
                ]);
                $authy_api = new AuthyApi(getenv("AUTHY_SECRET"));
                $res = $authy_api->verifyToken(auth()->user()->authy_id, $data['verification_code']);
                if ($res->bodyvar("success")) {
                    \session(['isVerified' => true]);
                    return redirect()->route('home');
                }
                return back()->with(['error' => $res->errors()->message]);
            } catch (\Throwable $th) {
                return back()->with(['error' => $th->getMessage()]);
            }
        }
    }

Taking a look at the `verify()` method you need to ensure that the data coming from the form is valid and has the `verification_code` property before proceeding to initialize the Twilio Authy SDK. To verify the OTP sent from the form data, make use of the `verifyToken()` method. This method takes in two arguments, the *user* `authy_id` and the `OTP`. Using the `[auth()](https://laravel.com/docs/6.x/helpers#method-auth)` helper function, you can retrieve the `authy_id` from the authenticated *user’s* model:

    $authy_api->verifyToken(auth()->user()->authy_id, $data['verification_code']);

Next, check that the request was successful before setting the `isVerified`  flag to `true` and redirecting the user to the home(dashboard) page:

    if ($res->bodyvar("success")) {
                    \session(['isVerified' => true]);
                    return redirect()->route('home');
                }

If the request isn’t successful, the user is redirected [back](https://laravel.com/docs/6.x/helpers#method-back) to the previous page with an `error` message.

### Updating the Authenticate Middleware
So far, you have been able to add 2FA to your Laravel application, but you still need to ensure unverified users do not have access to protected pages. Fortunately, Laravel supports [middlewares](https://laravel.com/docs/6.x/middleware) and also has a default [Authenticate](https://laravel.com/api/6.x/Illuminate/Auth/Middleware/Authenticate.html) middleware which is used to guard protected pages in our applications. You need to make changes to the default authenticate middleware to ensure a user OTP has been validated before granting access to protected pages. To do so, you will have to make adjustments to two middleware files; [Authenticate.php](https://laravel.com/api/6.x/Illuminate/Auth/Middleware/Authenticate.html) (ensures a user is authenticated to access a protected route) and `RedirectIfAuthenticated.php` (redirects a user if authenticated and accessing a guest route). Open up `app/Http/Middleware/Authenticate.php` and make the following changes:
 
    <?php
    namespace App\Http\Middleware;
    use Illuminate\Auth\Middleware\Authenticate as Middleware;
    class Authenticate extends Middleware
    {
        /**
         * Handle an incoming request.
         *
         * @param  \Illuminate\Http\Request  $request
         * @param  \Closure  $next
         * @param  string[]  ...$guards
         * @return mixed
         *
         * @throws \Illuminate\Auth\AuthenticationException
         */
        public function handle($request, $next, ...$guards)
        {
            $this->authenticate($request, $guards);
            if (session("isVerified")) {
                return $next($request);
            }
            return \redirect('verify');
        }
        /**
         * Get the path the user should be redirected to when they are not authenticated.
         *
         * @param  \Illuminate\Http\Request  $request
         * @return string
         */
        protected function redirectTo($request)
        {
            if (!$request->expectsJson()) {
                return route('login');
            }
        }
    }
    
The important bit here is in the `handle()`  method where you will check if the user is authenticated and `isVerified` is `true` before allowing the user to proceed with the request. Else, it redirects them to the verify page to get verified.
Open up `app/Http/Middleware/RedirectIfAuthenticated.php` and make the following changes:

    <?php
    namespace App\Http\Middleware;
    use Closure;
    use Illuminate\Support\Facades\Auth;
    class RedirectIfAuthenticated
    {
        /**
         * Handle an incoming request.
         *
         * @param  \Illuminate\Http\Request  $request
         * @param  \Closure  $next
         * @param  string|null  $guard
         * @return mixed
         */
        public function handle($request, Closure $next, $guard = null)
        {
            if (Auth::guard($guard)->check()) {
                if (\session('isVerified')) {
                    return redirect('/home');
                }
                return redirect('/verify');
            }
            return $next($request);
        }
    }
    
## Updating the views

At this point, you have added 2FA to your application authentication logic. Now, you will need to build out the views which users will use for interacting with your application. Fortunately, Laravel also scaffolds the basic views needed for registering and logging in to the application when the `make:auth` command is used. Although the registration view has been scaffolded, you still need to make changes to it to include the fields for getting the user’s phone number and country code. Open up `resources/views/auth/register.blade.php` and replace its content with the code below to add the needed fields:

    @extends('layouts.app')
    @section('content')
    <div class="container">
        <div class="row justify-content-center">
            <div class="col-md-8">
                <div class="card">
                    <div class="card-header">{{ __('Register') }}</div>
                    <div class="card-body">
                        <form method="POST" action="{{ route('register') }}">
                            @csrf
                            <div class="form-group row">
                                <label for="name" class="col-md-4 col-form-label text-md-right">{{ __('Name') }}</label>
                                <div class="col-md-6">
                                    <input id="name" type="text" class="form-control @error('name') is-invalid @enderror" name="name" value="{{ old('name') }}" required autocomplete="name" autofocus>
                                    @error('name')
                                        <span class="invalid-feedback" role="alert">
                                            <strong>{{ $message }}</strong>
                                        </span>
                                    @enderror
                                </div>
                            </div>
                            <div class="form-group row">
                                <label for="email" class="col-md-4 col-form-label text-md-right">{{ __('E-Mail Address') }}</label>
                                <div class="col-md-6">
                                    <input id="email" type="email" class="form-control @error('email') is-invalid @enderror" name="email" value="{{ old('email') }}" required autocomplete="email">
                                    @error('email')
                                        <span class="invalid-feedback" role="alert">
                                            <strong>{{ $message }}</strong>
                                        </span>
                                    @enderror
                                </div>
                            </div>
                            <div class="form-group row">
                                <label for="phone_number" class="col-md-4 col-form-label text-md-right">{{ __('Phone Number') }}</label>
                                <div class="col-md-6">
                                    <input id="phone_number" type="tel" class="form-control @error('phone_number') is-invalid @enderror" name="phone_number" value="{{ old('phone_number') }}" required>
                                    @error('phone_number')
                                        <span class="invalid-feedback" role="alert">
                                            <strong>{{ $message }}</strong>
                                        </span>
                                    @enderror
                                </div>
                            </div>
                            <div class="form-group row">
                                <label for="country_code" class="col-md-4 col-form-label text-md-right">{{ __('Country Code') }}</label>
                                <div class="col-md-6">
                                    <input id="country_code" type="tel" class="form-control @error('country_code') is-invalid @enderror" name="country_code" value="{{ old('country_code') }}" required>
                                    @error('country_code')
                                        <span class="invalid-feedback" role="alert">
                                            <strong>{{ $message }}</strong>
                                        </span>
                                    @enderror
                                </div>
                            </div>
                            <div class="form-group row">
                                <label for="password" class="col-md-4 col-form-label text-md-right">{{ __('Password') }}</label>
                                <div class="col-md-6">
                                    <input id="password" type="password" class="form-control @error('password') is-invalid @enderror" name="password" required autocomplete="new-password">
                                    @error('password')
                                        <span class="invalid-feedback" role="alert">
                                            <strong>{{ $message }}</strong>
                                        </span>
                                    @enderror
                                </div>
                            </div>
                            <div class="form-group row">
                                <label for="password-confirm" class="col-md-4 col-form-label text-md-right">{{ __('Confirm Password') }}</label>
                                <div class="col-md-6">
                                    <input id="password-confirm" type="password" class="form-control" name="password_confirmation" required autocomplete="new-password">
                                </div>
                            </div>
                            <div class="form-group row mb-0">
                                <div class="col-md-6 offset-md-4">
                                    <button type="submit" class="btn btn-primary">
                                        {{ __('Register') }}
                                    </button>
                                </div>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
        </div>
    </div>
    @endsection
    
Next, create a new file `resources/views/auth/verify.blade.php` which will present the user with a form to input the OTP sent to them via SMS. Now open up `resources/views/auth/verify.blade.php` and add the following content:

    @extends('layouts.app')
    @section('content')
    <div class="container">
        <div class="row justify-content-center">
            <div class="col-md-8">
                <div class="card">
                    <div class="card-header">{{ __('Verify Your Phone Number') }}</div>
                    <div class="card-body">
                        @if (session('error'))
                        <div class="alert alert-danger" role="alert">
                            {{session('error')}}
                        </div>
                        @endif
                        Please enter the OTP sent to your number: {{session('phone_number')}}
                        <form action="{{route('verify')}}" method="post">
                            @csrf
                            <div class="form-group row">
                                <label for="verification_code"
                                    class="col-md-4 col-form-label text-md-right">{{ __('OTP: ') }}</label>
                                <div class="col-md-6">
                                    <input id="verification_code" type="tel"
                                        class="form-control @error('verification_code') is-invalid @enderror"
                                        name="verification_code" value="{{ old('verification_code') }}" required>
                                    @error('verification_code')
                                    <span class="invalid-feedback" role="alert">
                                        <strong>{{ $message }}</strong>
                                    </span>
                                    @enderror
                                </div>
                            </div>
                            <div class="form-group row mb-0">
                                <div class="col-md-6 offset-md-4">
                                    <button type="submit" class="btn btn-primary">
                                        {{ __('Verify') }}
                                    </button>
                                </div>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
        </div>
    </div>
    @endsection
    
## Updating The Application Routes

Awesome! Now that the views have been updated, proceed to add the appropriate routes for the application. Open up `routes/web.php` and make the following changes:

    <?php
    /*
    |--------------------------------------------------------------------------
    | Web Routes
    |--------------------------------------------------------------------------
    |
    | Here is where you can register web routes for your application. These
    | routes are loaded by the RouteServiceProvider within a group which
    | contains the "web" middleware group. Now create something great!
    |
     */
    Route::get('/', function () {
        return view('welcome');
    });
    Route::get('/verify', 'VerifyController@index')->name('verify');
    Route::post('/verify', 'VerifyController@verify')->name('verify');
    Auth::routes();
    Route::get('/home', 'HomeController@index')->name('home');
    
## Testing Our Application

Now that you are done with building the application, let’s test it out. Open up your terminal and navigate to the project directory and run the following command:

    $ php artisan serve

This will serve your Laravel application on a localhost port, normally `8000`. Open up the localhost link printed out after running the command on your browser and you should be greeted with the default Laravel landing page with links to both the *register* and *login* page on the top right section of the header. You can proceed to register a user. If everything was coded correctly you will receive a OTP to verify your user’s session.

## Conclusion

Awesome! Now that you have completed this tutorial, you have learned how to make use of Twilio's Authy Service for securing your Laravel application with Two-factor authentication. Subsequently, you learned how to modify the default Laravel authentication system and work with traits in a Laravel application. If you would like to take a look at the complete source code for this tutorial, you can find it on [Github](https://github.com/thecodearcher/Laravel-2fa-twilio-authy).

I’d love to answer any question(s) you might have concerning this tutorial. You can reach me via:

- Email: [brian.iyoha@gmail.com](mailto:brian.iyoha@gmail.com)
- Twitter: [thecodearcher](https://twitter.com/thecodearcher)
- GitHub: [thecodearcher](https://github.com/thecodearcher)
