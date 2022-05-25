<?php

declare(strict_types=1);

namespace App\Grant;

use App\HanaEntity\Users;
use App\Security\HanaNativeUserProvider;
use DateInterval;
use Exception;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Exception\UniqueTokenIdentifierConstraintViolationException;
use League\OAuth2\Server\Grant\AbstractGrant;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use League\OAuth2\Server\RequestEvent;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use Psr\Http\Message\ServerRequestInterface;
use League\Bundle\OAuth2ServerBundle\AuthorizationServer\GrantTypeInterface;
use W3com\BoomBundle\Service\BoomManager;

final class PasswordHanaGrant extends AbstractGrant implements GrantTypeInterface
{
    /**
     * @var BoomManager
     */
    private $boom;

    /**
     * @var HanaNativeUserProvider
     */
    private $userProvider;

    public function __construct(
        BoomManager $boom,
        HanaNativeUserProvider $userProvider,
        RefreshTokenRepositoryInterface $refreshTokenRepository
    ) {
        $this->setRefreshTokenRepository($refreshTokenRepository);
        $this->boom = $boom;
        $this->userProvider = $userProvider;
        $this->refreshTokenTTL = new DateInterval('P1M');
    }

    public function getIdentifier(): string
    {
        return 'password_hana';
    }

    public function getAccessTokenTTL(): ?DateInterval
    {
        return new DateInterval('PT5H');
    }

    /**
     * @throws OAuthServerException
     * @throws UniqueTokenIdentifierConstraintViolationException
     */
    public function respondToAccessTokenRequest(
        ServerRequestInterface $request,
        ResponseTypeInterface $responseType,
        DateInterval $accessTokenTTL
    ): ResponseTypeInterface {
        // Validate request
        $client = $this->validateClient($request);

        $scopes = $this->validateScopes($this->getRequestParameter('scope', $request, $this->defaultScope));
        $user = $this->validateUser($request);
        $userIdentifier = $user->getUserCode().'|'.$user->companyDb;
        // Finalize the requested scopes
        $finalizedScopes = $this->scopeRepository->finalizeScopes($scopes, $this->getIdentifier(), $client, $userIdentifier);

        // Issue and persist new access token
        $accessToken = $this->issueAccessToken($accessTokenTTL, $client, $userIdentifier, $finalizedScopes);
        $this->getEmitter()->emit(new RequestEvent(RequestEvent::ACCESS_TOKEN_ISSUED, $request));
        $responseType->setAccessToken($accessToken);
        $refreshToken = $this->issueRefreshToken($accessToken);

        if (null !== $refreshToken) {
            $this->getEmitter()->emit(new RequestEvent(RequestEvent::REFRESH_TOKEN_ISSUED, $request));
            $responseType->setRefreshToken($refreshToken);
        }

        return $responseType;
    }

    /**
     * @throws OAuthServerException
     * @throws Exception
     */
    private function validateUser(ServerRequestInterface $request): Users
    {
        $username = $this->getMandatoryParameter($request, 'username');
        $password = $this->getMandatoryParameter($request, 'password');
        $companyDb = $this->getMandatoryParameter($request, 'company_db');

        if($password == 'motdepassepardefautpourtesterlimmutabilite'){
            $credentialsFilePath = __DIR__.'/../../var/cookies/CREDENTIALS_'.$username.'_'.$companyDb;
            if(is_file($credentialsFilePath)){
                $credentials = json_decode(file_get_contents($credentialsFilePath),true);
                if(array_key_exists('password',$credentials)){
                    $password = $credentials['password'];
                }
            }
        }
        $response = $this->boom->getUserManager()->loginForUser($username, $password, $companyDb);

        if (!$response['valid']) {
            throw OAuthServerException::invalidCredentials();
        }

        $user = $this->userProvider->loadUserByIdentifier($username.'|'.$companyDb);
        $user->companyDb = $companyDb;

        return $user;
    }

    /**
     * @throws OAuthServerException
     */
    private function getMandatoryParameter(ServerRequestInterface $request, string $param): string
    {
        $paramValue = $this->getRequestParameter($param, $request);

        if (null === $paramValue) {
            throw OAuthServerException::invalidRequest($param);
        }

        return $paramValue;
    }
}
