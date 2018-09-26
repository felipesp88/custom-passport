<?php

namespace Laravel\Passport\Http\Controllers;

use Illuminate\Http\Request;
use Zend\Diactoros\Response as Psr7Response;
use Laravel\Passport\Server\AuthorizationServer;

class ApproveAuthorizationController
{
    use HandlesOAuthErrors, RetrievesAuthRequestFromSession;

    /**
     * The authorization server.
     *
     * @var \Laravel\Passport\Server\AuthorizationServer
     */
    protected $server;

    /**
     * Create a new controller instance.
     *
     * @param  \Laravel\Passport\Server\AuthorizationServer  $server
     * @return void
     */
    public function __construct(AuthorizationServer $server)
    {
        $this->server = $server;
    }

    /**
     * Approve the authorization request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\Response
     */
    public function approve(Request $request)
    {
        return $this->withErrorHandling(function () use ($request) {
            $authRequest = $this->getAuthRequestFromSession($request);

            return $this->convertResponse(
                $this->server->completeAuthorizationRequest($authRequest, new Psr7Response)
            );
        });
    }
}
