<?php

namespace App\Http\Controllers;
use Illuminate\Http\Request;
use App\User;
use App\Admin;
use Validator, Hash;
use Illuminate\Support\Facades\Auth;
use App\Http\Controllers\Controller;
use JWTAuth;
use Response;
use Storage;
use Spatie\Permission\Models\Role;
use Spatie\Permission\Models\Permission;

class authcontroller extends Controller
{
  /**
     * Create a new AuthController instance.
     *
     * @return void
     */
    

    /**
     * Get a JWT via given credentials.
     *
     * @return \Illuminate\Http\JsonResponse
     */
   
        

    /**
     * Get the authenticated User.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function me()
    {
        config()->set( 'auth.defaults.guard', 'admins' );
        \Config::set('jwt.user', 'App\Admin'); 
        \Config::set('auth.providers.users.model', \App\Admin::class);
        return response()->json(auth()->user());
    }


     public function reset_password()
    {
        $input=Request()->all();
        
            if(Hash::check($input['old_password'], Admin::where('id',Auth::id())->value('password'))){
            Admin::where('id',Auth::id())->update(['password'=>hash::make($input['new_password'])
            ]);
            return ['state'=>202];
        }else{
   
            return Response()->json(['error'=>"old password doesn't right"]);
        }

         
    }


    /**
     * Log the user out (Invalidate the token).
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function logout()
    {
        auth()->logout();

        return response()->json(['message' => 'Successfully logged out']);
    }

     

    /**
     * Refresh a token.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function admins(){
        $input=Request()->all();
        if(isset($input['filter'] )){
            return Response()->json(['admins'=>Admin::withTrashed()->with('roles')->where('name','like','%'.$input['filter'].'%')->paginate(10)]);
       }else{
            return Response()->json(['admins'=>Admin::withTrashed()->with('roles')->paginate(10)]);  
        }
        }
    


    public function destroy($id){
        Admin::where('id',$id)->forceDelete();
        return Response()->json(['Admin'=>'deleted'],200);
    }
    public function trached($id){
        Admin::where('id',$id)->delete();
        return Response()->json(['Admin'=>'trached'],200);
    }
    public function cancel_trached($id){
        Admin::where('id',$id)->restore();
        return Response()->json(['Admin'=>'cancel_trached'],200);
    }


    public function refresh()
    {
        return $this->respondWithToken(auth()->refresh());
    }

    /**
     * Get the token array structure.
     *
     * @param  string $token
     *
     * @return \Illuminate\Http\JsonResponse
     */
    protected function respondWithToken($token)
    {
        return response()->json([
            'access_token' => $token,
            'token_type' => 'bearer',
            'expires_in' => auth()->factory()->getTTL() * 60,
            // 'permissions'=>auth()->user()->getAllPermissions(),
            'admin'=>Auth::user()
        ]);
    }


        public function adminLogin(Request $request){
    
        $validator = Validator::make($request->all(), [
            'email' => 'required|string|email|max:255',
            'password'=> 'required'
        ]);
        if ($validator->fails()) {
            return response()->json($validator->errors());
        }
        config()->set( 'auth.defaults.guard', 'admins' );
        \Config::set('jwt.user', 'App\Admin'); 
        \Config::set('auth.providers.users.model', \App\Admin::class);
        $credentials = $request->only('email', 'password');
        if ($token = JWTAuth::attempt($credentials)) {
    
            return $this->respondWithToken($token);
    
        }else{
    return response()->json(['error' => 'Unauthorized'], 401);
        }       
        

    }
    
    public function adminRegister(Request $request){
        
        $validator = Validator::make($request->all(), [
            'name'=>'required',
            // 'phone'=>'required',
            'email' => 'required|string|email|max:255|unique:admins|unique:users',
            'password'=> 'required'
        ]);
        if ($validator->fails()) {
            return response()->json($validator->errors());
        }
        config()->set( 'auth.defaults.guard', 'admins' );
        \Config::set('jwt.user', 'App\Admin'); 
        \Config::set('auth.providers.users.model', \App\Admin::class);
        $credentials = $request->only('phone','password','name','email','role');

        $credentials['password'] = hash::make($request->password);
        
        $admin = Admin::create(['name'=>$credentials['name'],'email'=>$credentials['email'],'password'=>$credentials['password']]);


    
        
        
        $credential = request(['email', 'password']);
        if ($token = JWTAuth::attempt($credential)) {
    
            return $this->respondWithToken($token);
    
        }else{
    return response()->json(['error' => 'Unauthorized'], 401);
        }       
        

    }
    public function getRoles($id){
        $admin=Admin::where('id',$id)->first();
        return $roles = $admin->getRoleNames(); // Returns a collection

    }
    
   
    public function editAdmin(Request $request,$id){
        
    $validator = Validator::make($request->all(), [
        'email' => 'required|string|email|max:255',
        'password'=> 'required'
    ]);
    if ($validator->fails()) {
        return response()->json($validator->errors());
    }
    config()->set( 'auth.defaults.guard', 'admins' );
    \Config::set('jwt.user', 'App\Admin'); 
    \Config::set('auth.providers.users.model', \App\Admin::class);
    $credentials = $request->only('phone','password','name','email');

    $credentials['password'] = hash::make($request->password);
    
    $admin = Admin::where('id',$id)->update($credentials);


    
    
    $credential = request(['email', 'password']);
    if ($token = JWTAuth::attempt($credential)) {

        return $this->respondWithToken($token);

    }else{
return response()->json(['error' => 'Unauthorized'], 401);
    }       
    

}
}
