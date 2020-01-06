Creating a New Laravel 6 Application
Let’s start by creating a new Laravel 6 application. Run the below command on the command line terminal to generate a new Laravel application.

composer create-project laravel/laravel JWTApp
It will create a new Laravel application in the folder named JWTApp. If you face any problem in installing Laravel, please check out our post on Install Laravel on Windows or Linux.

Installing JWT Authentication Package
Once you have the Laravel application created, we will install the tymondesigns/jwt-auth package for working with the JWT authentication in Laravel.


 
Run the below command in the terminal to install this package.

<b>composer require tymon/jwt-auth:dev-develop --prefer-source</b>

When package installation finishes run the below command to publish the package configurations.

<b>php artisan vendor:publish</b>

The above command will provide you a list of all discoverable packages, choose the Provider: Tymon\JWTAuth\Providers\LaravelServiceProvider from the list and hit enter.

You will have something like the below response in the console.

λ php artisan vendor:publish

 Which provider or tag's files would you like to publish?:
 
  [0 ] Publish files from all providers and tags listed below
  
  [1 ] Provider: Facade\Ignition\IgnitionServiceProvider
  
  [2 ] Provider: Fideloper\Proxy\TrustedProxyServiceProvider
  
  [3 ] Provider: Illuminate\Foundation\Providers\FoundationServiceProvider
  
  [4 ] Provider: Illuminate\Mail\MailServiceProvider
  
  [5 ] Provider: Illuminate\Notifications\NotificationServiceProvider
  
  [6 ] Provider: Illuminate\Pagination\PaginationServiceProvider
  
  [7 ] Provider: Laravel\Tinker\TinkerServiceProvider
  
  [8 ] Provider: Tymon\JWTAuth\Providers\LaravelServiceProvider
  
  [9 ] Tag: config
  
  [10] Tag: flare-config
  
  [11] Tag: ignition-config
  
  [12] Tag: laravel-errors
  
  [13] Tag: laravel-mail
  
  [14] Tag: laravel-notifications
  
  [15] Tag: laravel-pagination
  
 > 8
8

Copied File [\vendor\tymon\jwt-auth\config\config.php] To [\config\jwt.php]
Publishing complete.
Publishing complete.

Above command has generated a jwt.php configuration file in the config folder. Feel free to open this file and check which settings are available through this package.

Generating JWT Authentication Keys
JWT authentication token will be signed with an encryption key, run the following command to generate the secret key used to sign the tokens.

<b>php artisan jwt:secret</b>
You will have something like the below output.

λ php artisan jwt:secret
jwt-auth secret [pUSAT5tCxJLHT28RNGMLpbgis3J6MD2NUEDJQtgeGYJgwBVLk9kTwEA4WSNmn3og] set successfully.

Registering JWT Middleware
JWT package comes with a pre built middleware which we can use for our API routes. Open the app/Http/Kernel.php file and register this middleware with the name auth.jwt.

 /**
 * The application's route middleware.
 *
 * These middleware may be assigned to groups or used individually.
 *
 * @var array
 */
protected $routeMiddleware = [
    'auth' => \App\Http\Middleware\Authenticate::class,
    'auth.basic' => \Illuminate\Auth\Middleware\AuthenticateWithBasicAuth::class,
    'bindings' => \Illuminate\Routing\Middleware\SubstituteBindings::class,
    'cache.headers' => \Illuminate\Http\Middleware\SetCacheHeaders::class,
    'can' => \Illuminate\Auth\Middleware\Authorize::class,
    'guest' => \App\Http\Middleware\RedirectIfAuthenticated::class,
    'password.confirm' => \Illuminate\Auth\Middleware\RequirePassword::class,
    'signed' => \Illuminate\Routing\Middleware\ValidateSignature::class,
    'throttle' => \Illuminate\Routing\Middleware\ThrottleRequests::class,
    'verified' => \Illuminate\Auth\Middleware\EnsureEmailIsVerified::class,
    'auth.jwt'  =>  \Tymon\JWTAuth\Http\Middleware\Authenticate::class, // JWT middleware
];
This middleware will check if the user is authenticated by checking the token sent with the request if user is not authenticated it will throw an UnauthorizedHttpException exception.

Setting Up API Routes

 
In this section, we will setup our routes required for our this application. Open the routes/api.php file and copy the below routes to this file.

Route::post('login', 'ApiController@login');

Route::post('register', 'ApiController@register');

Route::post('forgot-password', 'APIController@sendResetLinkEmailApi');


Route::group(['middleware' => 'auth.jwt'], function () {
    Route::get('logout', 'ApiController@logout');
});


Updating User Model

JWT package we are using requires implementing the Tymon\JWTAuth\Contracts\JWTSubject interface on our User model. This interface requirews to implement two methods getJWTIdentifier and getJWTCustomClaims in our User model.

Open the app/User.php file and update with the below one.

namespace App;

use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use Tymon\JWTAuth\Contracts\JWTSubject;
class User extends Authenticatable implements JWTSubject
{
    use Notifiable;

    /**
     * The attributes that are mass assignable.
     *
     * @var array
     */
    protected $fillable = [
        'name', 'email', 'password',
    ];

    /**
     * The attributes that should be hidden for arrays.
     *
     * @var array
     */
    protected $hidden = [
        'password', 'remember_token',
    ];

    /**
     * The attributes that should be cast to native types.
     *
     * @var array
     */
    protected $casts = [
        'email_verified_at' => 'datetime',
    ];

    /**
     * Get the identifier that will be stored in the subject claim of the JWT.
     *
     * @return mixed
     */
    public function getJWTIdentifier()
    {
        return $this->getKey();
    }

    /**
     * Return a key value array, containing any custom claims to be added to the JWT.
     *
     * @return array
     */
    public function getJWTCustomClaims()
    {
        return [];
    }
}
Creating Registration Form Request
From now on, we will start actually implementing the logic required for our API. Firstly, we will create a form request for registration purpose. User registration will require name, email, and password. So let’s create the form request class to handle this validation.

We will create a new form request class RegistrationFormRequest by running the command below.

php artisan make:request RegistrationFormRequest
It will create RegistrationFormRequest.php file in the app/Http/Requests folder.

Open this class and replace the code with below one:

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

class RegistrationFormRequest extends FormRequest
{
    /**
     * Determine if the user is authorized to make this request.
     *
     * @return bool
     */
    public function authorize()
    {
        return true;
    }

    /**
     * Get the validation rules that apply to the request.
     *
     * @return array
     */
    public function rules()
    {
        return [
            'name' => 'required|string',
            'email' => 'required|email|unique:users',
            'password' => 'required|string|min:6|max:10'
        ];
    }
}
Creating API Controller for Login and Registration
Now, we will create a new controller class and name it APIController. Run the below command to generate this controller.

php artisan make:controller APIController
This will generate a new controller in the app/Http/Controllers folder. Open this controller and update with the below controller class.

namespace App\Http\Controllers;

use Illuminate\Support\Facades\Password;
use Illuminate\Support\Facades\Validator;
use JWTAuth;
use App\User;
use Illuminate\Http\Request;
use Tymon\JWTAuth\Exceptions\JWTException;

class APIController extends Controller
{
    /**
     * @var bool
     */
    public $loginAfterSignUp = true;

    /**
     * @param Request $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function login(Request $request)
    {
        $input = $request->only('email', 'password');
        $token = null;

        if (!$token = JWTAuth::attempt($input)) {
            return response()->json([
                'success' => false,
                'message' => 'Invalid Email or Password',
            ], 401);
        }

        return response()->json([
            'success' => true,
            'token' => $token,
        ]);
    }

    /**
     * @param Request $request
     * @return \Illuminate\Http\JsonResponse
     * @throws \Illuminate\Validation\ValidationException
     */
    public function logout(Request $request)
    {
        $this->validate($request, [
            'token' => 'required'
        ]);

        try {
            JWTAuth::invalidate($request->token);

            return response()->json([
                'success' => true,
                'message' => 'User logged out successfully'
            ]);
        } catch (JWTException $exception) {
            return response()->json([
                'success' => false,
                'message' => 'Sorry, the user cannot be logged out'
            ], 500);
        }
    }

    /**
     * @param Request $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function register(Request $request)
    {
        $input = $request->all();
        $rules = [
            'name'  => 'required',
            'email'  => 'required|email|unique:users,email',
            'password'  => 'required',
        ];
        $validator = Validator::make($input, $rules);
        if ($validator->fails()) {
            return response()->json($validator->messages(), 422);
        }
        $user = new User();
        $user->name = $request->name;
        $user->email = $request->email;
        $user->password = bcrypt($request->password);
        $user->save();

        if ($this->loginAfterSignUp) {
            return $this->login($request);
        }

        return response()->json([
            'success'   =>  true,
            'data'      =>  $user
        ], 200);
    }

    /**
     * @param Request $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function sendResetLinkEmailApi(Request $request)
    {
        $credentials = $request->only('email');
        $rules = [
            'email' => 'required|email',
        ];
        $validator = Validator::make($credentials, $rules);
        if ($validator->fails()) {
            return response()->json($validator->messages(), 422);
        }
        $user = User::whereEmail($request->input()['email'])->first();
        if (!is_null($user)) {
            // We will send the password reset link to this user. Once we have attempted
            // to send the link, we will examine the response then see the message we
            // need to show to the user. Finally, we'll send out a proper response.
            $response = $this->broker()->sendResetLink(
                $request->only('email')
            );

            return $response == Password::RESET_LINK_SENT
                ? response()->json(['message' => 'Reset link has been sent', 'status' => true], 201)
                : response()->json(['message' => 'Unable to send reset link', 'status' => false], 401);
        } else {
            return response()->json(['error' => 'Invalid email address'], 404);
        }
    }

    /**
     * Get the broker to be used during password reset.
     *
     * @return \Illuminate\Contracts\Auth\PasswordBroker
     */
    public function broker()
    {
        return Password::broker();
    }
}

In the above controller class, we firstly added all the required classes. Then we have defined a public property $loginAfterSignUp which we will use in our register() method.

First, function we added is the login(). In this function, we firstly get the subset data from the form request only containing email and password. By using the JWTAuth::attempt($input) method, we determine if the authentication is successful and save the response in the $token variable. If the response is false, then we are sending the error message back in JSON format. If the authentication return true then we send the success response along with the $token.

Next, we added the logout() method which invalidate the token. Firstly, we get the token from the form request and validate it, then call the JWTAuth::invalidate() method by passing the token from a form request. If the response is true we return the success message. If any exception occurs then we are sending an error message back.

In the final, register() method we get the data from the form request and create a new instance of the User model and save it. Then we check if the our public property $loginAfterSignup is set we call the login() method to authenticate the user and send the success response back.
