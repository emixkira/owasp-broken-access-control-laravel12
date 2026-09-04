<?php

namespace App\Actions\Fortify;

use App\Models\User;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use Laravel\Fortify\Http\Requests\LoginRequest;

class AuthenticateUser
{
    public function __invoke(LoginRequest $request)
    {
        $credentials = $request->only(
            'email',
            'password'
        );

        $user = User::where(
            'email',
            $credentials['email']
        )->first();

        if (!$user) {
            return null;
        }

        /*
        |--------------------------------------------------------------------------
        | OLD USERS MIGRATION
        |--------------------------------------------------------------------------
        |
        | Gli utenti creati prima dell'introduzione di salt + pepper
        | hanno il campo salt a null.
        |
        | Se la vecchia password è corretta, generiamo automaticamente
        | il salt e aggiorniamo la password al nuovo sistema.
        |
        */

        if (is_null($user->salt)) {
            if (
                Hash::check(
                    $credentials['password'],
                    $user->password
                )
            ) {
                $salt = Str::random(32);

                $passwordWithSaltPepper =
                    $credentials['password']
                    . $salt
                    . config('app.pepper');

                $user->salt = $salt;

                $user->password = Hash::make(
                    $passwordWithSaltPepper
                );

                $user->save();

                Auth::login($user);

                return $user;
            }

            return null;
        }

        /*
        |--------------------------------------------------------------------------
        | NEW USERS - SALT + PEPPER
        |--------------------------------------------------------------------------
        */

        $pepper = config('app.pepper');

        $passwordWithSaltPepper =
            $credentials['password']
            . $user->salt
            . $pepper;

        if (
            Hash::check(
                $passwordWithSaltPepper,
                $user->password
            )
        ) {
            Auth::login($user);

            return $user;
        }

        return null;
    }
}