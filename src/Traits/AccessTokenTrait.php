<?php
/**
 * Created by PhpStorm.
 * User: Felipe
 * Date: 17/10/2018
 * Time: 09:45
 */

namespace Laravel\Passport\Traits;

use Laravel\Passport\Passport;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Token;
use League\OAuth2\Server\CryptKey;

trait AccessTokenTrait
{
    use \League\OAuth2\Server\Entities\Traits\AccessTokenTrait;

    /**
     * Generate a JWT from the access token
     *
     * @param CryptKey $privateKey
     *
     * @return Token
     */
    public function convertToJWT(CryptKey $privateKey)
    {
        $secondary = $this->getSecondaryAudiences();

        $provider = config('auth.guards.api.provider');
        if (is_null($model = config('auth.providers.'.$provider.'.model'))) {
            throw new \RuntimeException('Unable to determine authentication model from configuration.');
        }
        $user = (new $model)->find($this->getUserIdentifier());

        return (new Builder())
            ->setIssuer(str_finish(config('app.url'), '/'))
            ->setAudience($this->getClient()->getIdentifier() . (empty($secondary) ? '' : (' ' . $secondary)))
            ->setId($this->getIdentifier(), true)
            ->setIssuedAt(time())
            ->setNotBefore(time())
            ->setExpiration($this->getExpiryDateTime()->getTimestamp())
            ->setSubject(optional($user)->user_id)
            ->set('scopes', $this->getScopes())
            ->sign(new Sha256(), new Key($privateKey->getKeyPath(), $privateKey->getPassPhrase()))
            ->getToken();
    }

    /**
     * @return string
     */
    public function getSecondaryAudiences()
    {
        return implode(' ', Passport::client()->where('secondary', true)->get()->pluck('id')->toArray());
    }
}
