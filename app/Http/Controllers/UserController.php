<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Storage;
use Intervention\Image\Facades\Image as Image;

class UserController extends Controller
{
    /*
    |--------------------------------------------------------------------------
    | PROFILE - SECURE
    |--------------------------------------------------------------------------
    |
    | Il profilo viene recuperato direttamente dall'utente autenticato.
    | Non viene più utilizzato un ID ricevuto dalla URL.
    |
    */

    public function profile()
    {
        $user = Auth::user();

        if (!$user) {
            return response()->json([
                'message' => 'Forbidden Operation'
            ], 403);
        }

        return view('auth.profile', compact('user'));
    }


    public function update(Request $request, $id)
    {
        $user = User::find($id);

        $user->update($request->all());

        return back()->with('message', 'User updated');
    }


    public function changeEmail(Request $request)
    {
        if (!$user = Auth::user()) {
            return response()->json([
                'message' => 'Forbidden Operation'
            ], 403);
        }

        $user->email = $request->email;
        $user->save();

        return back()->with(
            'message',
            'Changed successfully'
        );
    }


    public function changeName(Request $request)
    {
        if (!$user = Auth::user()) {
            return response()->json([
                'message' => 'Forbidden Operation'
            ], 403);
        }

        $user->name = $request->name;
        $user->save();

        return back()->with(
            'message',
            'Changed successfully'
        );
    }


    public function changeImg(Request $request)
    {
        if (!$user = Auth::user()) {
            return back()->with(
                'message',
                'Please Log In'
            );
        }

        if (!$request->hasFile('avatar')) {
            return back()->with(
                'message',
                'Forbidden Operation'
            );
        }

        if (
            !file_exists(
                storage_path(
                    "app/public/images/users/" . $user->id
                )
            )
        ) {
            mkdir(
                storage_path(
                    "app/public/images/users/" . $user->id
                ),
                0777,
                true
            );
        }

        $newImage = $request->file('avatar');

        /*
        |--------------------------------------------------------------------------
        | CRYPTOGRAPHIC FAILURE
        |--------------------------------------------------------------------------
        |
        | Questa parte è ancora volutamente vulnerabile.
        | La sistemeremo nella relativa esercitazione.
        |
        */

        $newImageHash = md5_file($newImage);

        // SECURE:
        // $newImageHash = hash_file(
        //     'sha256',
        //     $newImage
        // );

        if ($newImageHash == $user->avatar) {
            return redirect()
                ->back()
                ->with(
                    'message',
                    'Image not updated, same'
                );
        }

        $path = "images/users/" . $user->id;

        Storage::deleteDirectory($path);

        $newImage->storeAs(
            $path,
            $newImageHash,
            'public'
        );

        $user->avatar = $newImageHash;
        $user->save();

        return redirect()
            ->back()
            ->with(
                'message',
                'Image updated'
            );
    }


    /*
    |--------------------------------------------------------------------------
    | DOWNLOAD DOCUMENTS - SECURE
    |--------------------------------------------------------------------------
    |
    | Il nome del file non viene più accettato liberamente.
    | Possono essere scaricati soltanto i documenti presenti
    | nella whitelist.
    |
    */

    public function download(Request $request)
    {
        $filename = $request->get('filename');

        $allowedFiles = [
            'privacy.pdf',
            'cookie-policy.pdf',
        ];

        if (!in_array($filename, $allowedFiles, true)) {
            abort(403, 'Forbidden');
        }

        $path = storage_path(
            'app/private/' . $filename
        );

        if (!file_exists($path)) {
            abort(404);
        }

        return response()->download($path);
    }


    public function upload(Request $request)
    {
        if (!$user = Auth::user()) {
            return back()->with(
                'message',
                'Please Log In'
            );
        }

        if (!$request->hasFile('file')) {
            return back()->withErrors(
                'Forbidden Operation'
            );
        }

        $path = storage_path(
            "app/public/docs/users/" . $user->id
        );

        if (!file_exists($path)) {
            mkdir(
                $path,
                0777,
                true
            );
        }

        $file = $request->file('file');

        /*
        |--------------------------------------------------------------------------
        | FILE UPLOAD - UNSECURE
        |--------------------------------------------------------------------------
        |
        | Questa parte rimane volutamente vulnerabile.
        | La correggeremo nella relativa esercitazione OWASP.
        |
        */

        $filename =
            $file->getClientOriginalName();

        $file->move(
            $path,
            $filename
        );

        /*
        |--------------------------------------------------------------------------
        | SECURE VERSION - DA IMPLEMENTARE SUCCESSIVAMENTE
        |--------------------------------------------------------------------------
        |
        | Controllo estensione
        | Controllo MIME type
        | Nome file sicuro
        | Storage privato
        |
        */

        return back()->withMessage(
            'Upload successful'
        );
    }
}