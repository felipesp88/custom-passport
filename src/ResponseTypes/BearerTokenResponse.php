<?php

namespace Laravel\Passport\ResponseTypes;

use Laravel\Passport\Traits\OpenIDToken;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\ResponseTypes\BearerTokenResponse as BearerResponse;

class BearerTokenResponse extends BearerResponse
{
    use OpenIDToken;

    /**
     * @param AccessTokenEntityInterface $accessToken
     * @return array
     */
    protected function getExtraParams(AccessTokenEntityInterface $accessToken)
    {
        if (in_array('openid', $accessToken->getScopes())) {

            return ['id_token' => $this->getOpenIDToken($accessToken->getUserIdentifier(),
                $accessToken->getClient()->getIdentifier(), $accessToken->getExpiryDateTime()->getTimestamp())];
        }

        return [];
    }
}