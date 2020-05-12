<?php

namespace App\Security;

use App\Entity\User;
use HWI\Bundle\OAuthBundle\Connect\AccountConnectorInterface;
use HWI\Bundle\OAuthBundle\Security\Core\User\EntityUserProvider;
use HWI\Bundle\OAuthBundle\OAuth\Response\UserResponseInterface;
use PhpParser\Node\Expr\FuncCall;
use Symfony\Component\PropertyAccess\PropertyAccess;
use Symfony\Component\Security\Core\Exception\UnsupportedUserException;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use Symfony\Component\Security\Core\User\UserInterface;

class MyEntityUserProvider extends EntityUserProvider  implements AccountConnectorInterface {

    public function loadUserByOAuthUserResponse(UserResponseInterface $response)
    {
        $resourceOwnerName = $response->getResourceOwner()->getName();
    
        if(!isset($this->properties[$resourceOwnerName])) {
            throw new \RuntimeException(sprintf("No property defined for the entity resource"));
        }

        $serviceName = $response->getResourceOwner()->getName();
        $setterId = 'set'. ucfirst($serviceName) . 'ID';
        $setterAccessToken = 'set' . ucfirst($serviceName) . 'AccessToken';

        $username = $response->getUsername();
        if (null === $user = $this->findUser(array($this->properties[$resourceOwnerName] =>$username))) {
            $user = new User();

            $user->setEmail($response->getEmail());
            $user->$setterId($username);
            $user->$setterAccessToken($response->getAccessToken());

            $this->em->persist($user);
            $this->em->flush();

            return $user;
        }

        $user->setFacebookAccessToken($response->getAccessToken());

        return $user;
    }

    public function connect(UserInterface $user, UserResponseInterface $response)
    {
        if(!$user instanceof User) {
            throw new UnsupportedUserException(sprintf('Expected an instance of App\Model\User'));
        }

        $property = $this->getProperty($response);
        $username = $response->getUsername();

        if(null !== $previousUser = $this->registry->getRepository(User::class)->findOneBy(array($property => $username))) {
            $this->disconnect($previousUser, $response);
        }

        $serviceName = $response->getResourceOwner()->getName();
        $setter = 'set'. ucfirst($serviceName) . 'AccessToken';

        $user->$setter($response->getAccessToken());

        $this->updateUser($user, $response);
    }

    protected function getProperty(UserResponseInterface $response)
    {
        $resourceOwnerName = $response->getResourceOwner()->getName();

        if(!isset($this->properties[$resourceOwnerName])) {
            throw new \RuntimeException(sprintf("No property defined for entity for resource owner"));
        }

        return $this->properties[$resourceOwnerName];
    }

  /**
   * Disconnect the user if its already connected.
   * @param UserInterface $user
   * @param UserResponseInterface $response
   */
    protected function disconnect(UserInterface $user, UserResponseInterface $response)
    {
        $property = $this->getProperty($response);
        $accessor = PropertyAccess::createPropertyAccessor();

        $accessor->setValue($user, $property, null);

        $this->updateUser($user, $response);
    }

    protected function updateUser(UserInterface $user, UserResponseInterface $response)
    {
        $user->setEmail($response->getEmail());

        $this->em->persist($user);
        $this->em->flush();
    }

}