<?php

namespace Laravel\Passport\Traits;


use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use RuntimeException;

trait OpenIDToken
{
    /**
     * @param string $user_id
     * @param string $client_id
     * @param int $expires_at
     * @return \Lcobucci\JWT\Token
     */
    public function getOpenIDToken(string $user_id, string $client_id, int $expires_at)
    {
        $provider = config('auth.guards.api.provider');
        if (is_null($model = config('auth.providers.'.$provider.'.model'))) {
            throw new RuntimeException('Unable to determine authentication model from configuration.');
        }

        $user = (new $model)->find($user_id);
        if (!$user) {
            throw new RuntimeException('Unable to find model with specific identifier.');
        }

        $token = (new Builder())->setIssuer(env('APP_URL'))
            ->setSubject($user_id)
            ->setAudience($client_id)
            ->setExpiration($expires_at)
            ->setIssuedAt(time())
            ->setNotBefore(time())
            ->set('auth_time', time());

        foreach (config('passport.special_claims') as $calim) {
            $token = $token->set($calim, $user->$calim);
        }

        if (\Request::has('nonce')) {
            $token = $token->set('nonce', \Request::get('nonce'));
        }

        return $token->sign(new Sha256(), new Key('file://'. config('passport.private_key')))
            ->getToken();
    }
}