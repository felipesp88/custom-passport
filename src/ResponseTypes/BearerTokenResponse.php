<?php
/**
 * Created by PhpStorm.
 * User: Felipe
 * Date: 17/10/2018
 * Time: 10:39
 */

namespace Laravel\Passport\ResponseTypes;

use Laravel\Passport\Traits\OpenIDTokenTrait;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;

class BearerTokenResponse extends \League\OAuth2\Server\ResponseTypes\BearerTokenResponse
{
    use OpenIDTokenTrait;
    /**
     * Add custom fields to your Bearer Token response here, then override
     * AuthorizationServer::getResponseType() to pull in your version of
     * this class rather than the default.
     *
     * @param AccessTokenEntityInterface $accessToken
     *
     * @return array
     */
    protected function getExtraParams(AccessTokenEntityInterface $accessToken)
    {
        $array = parent::getExtraParams($accessToken);

        foreach ($accessToken->getScopes() as $scope) {
            if ($scope->getIdentifier() === 'openid') {
                $array['id_token'] = (string) $this->getOpenIDToken($accessToken->getUserIdentifier(),
                    $accessToken->getClient()->getIdentifier(), $accessToken->getExpiryDateTime()->getTimestamp());
            }
        }

        return $array;
    }
}