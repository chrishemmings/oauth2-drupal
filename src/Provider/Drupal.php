<?php

namespace ChrisHemmings\OAuth2\Client\Provider;

use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Provider\ResourceOwnerInterface;
use League\OAuth2\Client\Token\AccessToken;
use League\OAuth2\Client\Tool\BearerAuthorizationTrait;
use Psr\Http\Message\ResponseInterface;

class Drupal extends AbstractProvider
{
    use BearerAuthorizationTrait;

    protected $baseUrl;

    public function getBaseUrl()
    {
        return $this->baseUrl;
    }

    /**
     * Get provider url to run authorization
     *
     * @return string
     */
    public function getBaseAuthorizationUrl()
    {
        return $this->getBaseUrl() . '/oauth/authorize';
    }

    /**
     * Returns the base URL for requesting an access token.
     *
     * @param array $params
     * @return string
     */
    public function getBaseAccessTokenUrl(array $params)
    {
        return $this->getBaseUrl() . '/oauth/token';
    }

    /**
     * Get provider url to fetch user details
     *
     * @param AccessToken $token
     * @return string
     */
    public function getResourceOwnerDetailsUrl(AccessToken $token)
    {
        return $this->getBaseUrl() . '/oauth/UserInfo';
    }

    /**
     * Get the default scopes used by this provider.
     *
     * @return array
     */
    protected function getDefaultScopes()
    {
        return ['openid', 'email', 'profile'];
    }

    /**
     * Returns the string that should be used to separate scopes when building
     * the URL for requesting an access token.
     *
     * @return string Scope separator, defaults to ' '
     */
    protected function getScopeSeparator()
    {
        return ' ';
    }

    /**
     * Check a provider response for errors.
     *
     * @param ResponseInterface $response
     * @param array|string $data
     *
     * @throws IdentityProviderException
     */
    protected function checkResponse(ResponseInterface $response, $data)
    {
        if ($response->getStatusCode() >= 400) {
            throw new IdentityProviderException(
                $data['error'] ?: $response->getReasonPhrase(),
                $response->getStatusCode(),
                $response
            );
        }
    }

    /**
     * Generate a user object from a successful user details request.
     *
     * @param array $response
     * @param AccessToken $token
     *
     * @return League\OAuth2\Client\Provider\ResourceOwnerInterface
     */
    protected function createResourceOwner(array $response, AccessToken $token)
    {
        return new DrupalResourceOwner($response);
    }
}
