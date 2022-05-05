<?php

namespace App\Security;

use App\HanaEntity\Users;
use function count;
use Exception;
use function get_class;
use Symfony\Component\Security\Core\Exception\UnsupportedUserException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;

class HanaNativeUserProvider extends AbstractHanaUserProvider implements UserProviderInterface
{
    /**
     * UserIdentifier (From oauth_access_token.userIdentifier when Bearer token (Authorization))
     * UserIdentifier (From users.username when request new access_token).
     *
     * @throws Exception
     */
    public function loadUserByIdentifier(string $userIdentifier): Users
    {
        // If from oauth_access_token.userIdentifier, need to set currentConnection
        if (count(explode('|', $userIdentifier)) > 1) {
            $username = explode('|', $userIdentifier)[0];
            $companyDb = explode('|', $userIdentifier)[1];
            $this->boom->getUserManager()->setConnectedUser($username, $companyDb,false);
        }

        $guessUsername = isset($username) ? $username : $userIdentifier;

        $user = $this->findOneBy('Users', 'userCode', $guessUsername);
        if(isset($companyDb)){
            $user->companyDb = $companyDb;
        }
        return $user;
    }

    /**
     * @throws Exception
     */
    public function refreshUser(UserInterface $user): void
    {
        if (!$user instanceof Users) {
            throw new UnsupportedUserException(sprintf('Invalid user class "%s".', get_class($user)));
        }
    }

    public function supportsClass(string $class): bool
    {
        return Users::class === $class || is_subclass_of($class, Users::class);
    }
}
