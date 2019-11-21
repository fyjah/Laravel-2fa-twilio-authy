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
