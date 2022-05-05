<?php

namespace App\Security;

use function count;
use Exception;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use W3com\BoomBundle\Service\BoomManager;

abstract class AbstractHanaUserProvider
{
    /**
     * @var BoomManager
     */
    protected $boom;

    public function __construct(BoomManager $boom)
    {
        $this->boom = $boom;
    }

    /**
     * @throws Exception
     *
     * @return mixed
     */
    public function findOneBy(string $repo, string $usernameProperty, string $username)
    {
        $repo = $this->boom->getRepository($repo);
        $params = $repo->createParams()->addFilter($usernameProperty, $username);
        $users = $repo->findAll($params);

        if (1 === count($users)) {
            return $users[0];
        }
        throw new UsernameNotFoundException();
    }
}
