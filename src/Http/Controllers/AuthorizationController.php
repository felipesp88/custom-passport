<?php

namespace Laravel\Passport\Http\Controllers;

use Illuminate\Http\Request;
use Laravel\Passport\Passport;
use Laravel\Passport\Bridge\User;
use Laravel\Passport\Server\AuthorizationServer;
use Laravel\Passport\TokenRepository;
use Laravel\Passport\ClientRepository;
use Illuminate\Database\Eloquent\Model;
use Psr\Http\Message\ServerRequestInterface;
use Zend\Diactoros\Response as Psr7Response;
use Illuminate\Contracts\Routing\ResponseFactory;
use League\OAuth2\Server\RequestTypes\AuthorizationRequest;

class AuthorizationController
{
    use HandlesOAuthErrors;

    /**
     * The authorization server.
     *
     * @var \Laravel\Passport\Server\AuthorizationServer
     */
    protected $server;

    /**
     * The response factory implementation.
     *
     * @var \Illuminate\Contracts\Routing\ResponseFactory
     */
    protected $response;

    /**
     * Create a new controller instance.
     *
     * @param  \Laravel\Passport\Server\AuthorizationServer  $server
     * @param  \Illuminate\Contracts\Routing\ResponseFactory  $response
     * @return void
     */
    public function __construct(AuthorizationServer $server, ResponseFactory $response)
    {
        $this->server = $server;
        $this->response = $response;
    }

    /**
     * Authorize a client to access the user's account.
     *
     * @param  \Psr\Http\Message\ServerRequestInterface  $psrRequest
     * @param  \Illuminate\Http\Request  $request
     * @param  \Laravel\Passport\ClientRepository  $clients
     * @param  \Laravel\Passport\TokenRepository  $tokens
     * @return \Illuminate\Http\Response
     */
    public function authorize(ServerRequestInterface $psrRequest,
                              Request $request,
                              ClientRepository $clients,
                              TokenRepository $tokens)
    {
        return $this->withErrorHandling(function () use ($psrRequest, $request, $clients, $tokens) {
            $authRequest = $this->server->validateAuthorizationRequest($psrRequest);

            $scopes = $this->parseScopes($authRequest);

            $token = $tokens->findValidToken(
                $user = $request->user(),
                $client = $clients->find($authRequest->getClient()->getIdentifier())
            );

            if ($token && $token->scopes === collect($scopes)->pluck('id')->all()) {
                return $this->approveRequest($authRequest, $user);
            }

            return $this->approveRequest($authRequest, $user);
        });
    }

    /**
     * Transform the authorization requests's scopes into Scope instances.
     *
     * @param  \League\OAuth2\Server\RequestTypes\AuthorizationRequest  $authRequest
     * @return array
     */
    protected function parseScopes($authRequest)
    {
        return Passport::scopesFor(
            collect($authRequest->getScopes())->map(function ($scope) {
                return $scope->getIdentifier();
            })->unique()->all()
        );
    }

    /**
     * Approve the authorization request.
     *
     * @param  \League\OAuth2\Server\RequestTypes\AuthorizationRequest  $authRequest
     * @param  \Illuminate\Database\Eloquent\Model  $user
     * @return \Illuminate\Http\Response
     */
    protected function approveRequest($authRequest, $user)
    {
        $authRequest->setUser(new User($user->getKey()));

        $authRequest->setAuthorizationApproved(true);

        return $this->convertResponse(
            $this->server->completeAuthorizationRequest($authRequest, new Psr7Response)
        );
    }
}
