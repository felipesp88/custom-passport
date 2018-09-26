<?php

namespace Laravel\Passport\Traits;

use Laravel\Passport\Passport;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Token;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;

trait AccessTokenTrait
{
    /**
     * Generate a JWT from the access token
     *
     * @param CryptKey $privateKey
     *
     * @return Token
     */
    public function convertToJWT(CryptKey $privateKey)
    {
        return (new Builder())
            ->setAudience(implode(' ', array_prepend($this->getSecondaryAudiences(), $this->getClient()->getIdentifier())))
            ->setId($this->getIdentifier(), true)
            ->setIssuedAt(time())
            ->setNotBefore(time())
            ->setExpiration($this->getExpiryDateTime()->getTimestamp())
            ->setSubject($this->getUserIdentifier())
            ->set('scopes', $this->getScopes())
            ->sign(new Sha256(), new Key($privateKey->getKeyPath(), $privateKey->getPassPhrase()))
            ->getToken();
    }

    /**
     * @return ClientEntityInterface
     */
    abstract public function getClient();

    /**
     * @return \DateTime
     */
    abstract public function getExpiryDateTime();

    /**
     * @return string|int
     */
    abstract public function getUserIdentifier();

    /**
     * @return ScopeEntityInterface[]
     */
    abstract public function getScopes();

    /**
     * @return array
     */
    public function getSecondaryAudiences()
    {
        return Passport::client()->where('secondary', true)->get()->pluck('_id')->toArray();
    }
}