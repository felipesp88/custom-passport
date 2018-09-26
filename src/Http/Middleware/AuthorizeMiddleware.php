<?php

namespace Laravel\Passport\Http\Middleware;

use function GuzzleHttp\Psr7\parse_query;
use Laravel\Passport\Passport;
use Laravel\Passport\Traits\OpenIDToken;

class AuthorizeMiddleware
{
    use OpenIDToken;

    /**
     * @param $request
     * @param \Closure $next
     * @return mixed
     */
    public function handle($request, \Closure $next)
    {
        $openid = in_array('openid', explode(' ', $request->query('scope')));

        $response = $next($request);

        if ($openid && $response->isRedirect()) {
            $location = $response->headers->get('location');
            if (starts_with($location, $request->query('redirect_uri'))) {
                $query = parse_query(parse_url($location)['query']);
                if (!isset($query['error'])
                    && in_array('id_token', explode(' ', $request->query('response_type')))) {
                    $queryString = http_build_query(['id_token' =>
                        $this->getOpenIDToken(\Auth::id(), $request->query('client_id'), Passport::$tokensExpireAt->getTimestamp())]);
                    $response->headers->set('location', $location . "&$queryString");
                }
            }
        }

        return $response;
    }
}