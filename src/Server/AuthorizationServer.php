<?php
/**
 * Created by PhpStorm.
 * User: Felipe
 * Date: 17/10/2018
 * Time: 10:28
 */

namespace Laravel\Passport\Server;

use Laravel\Passport\ResponseTypes\BearerTokenResponse;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;

class AuthorizationServer extends \League\OAuth2\Server\AuthorizationServer
{
    /**
     * Get the token type that grants will return in the HTTP response.
     *
     * @return ResponseTypeInterface
     */
    protected function getResponseType()
    {
        if ($this->responseType instanceof ResponseTypeInterface === false) {
            return $this->responseType = new BearerTokenResponse();
        }

        return parent::getResponseType();
    }
}