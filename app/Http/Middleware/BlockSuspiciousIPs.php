<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\RateLimiter;
use Symfony\Component\HttpFoundation\Response;

class BlockSuspiciousIPs
{
    /**
     * Handle an incoming request.
     *
     * @param  \Closure(\Illuminate\Http\Request): (\Symfony\Component\HttpFoundation\Response)  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        $ip = $request->ip();

        $key = 'comments:' . $ip;

        if (RateLimiter::tooManyAttempts($key, 5)) {
            abort(
                429,
                'Too many comments. Please try again later.'
            );
        }

        RateLimiter::hit($key, 60);

        return $next($request);
    }
}