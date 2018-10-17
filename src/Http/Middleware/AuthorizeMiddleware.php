<?php
/**
 * Created by PhpStorm.
 * User: Felipe
 * Date: 17/10/2018
 * Time: 11:08
 */

namespace Laravel\Passport\Http\Middleware;

use Illuminate\Http\Request;
use Laravel\Passport\Passport;
use Laravel\Passport\Traits\OpenIDTokenTrait;

class AuthorizeMiddleware
{
    use OpenIDTokenTrait;

    /**
     * @param Request $request
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
                $query = \GuzzleHttp\Psr7\parse_query(parse_url($location)['query']);
                if (!isset($query['error'])
                    && in_array('id_token', explode(' ', $request->query('response_type')))) {
                    $queryString = http_build_query(['id_token' => (string)
                    $this->getOpenIDToken(\Auth::user()->id, $request->query('client_id'), Passport::$tokensExpireAt->getTimestamp())]);
                    $response->headers->set('location', $location . "&$queryString");
                }
            }
        }
        return $response;
    }
}