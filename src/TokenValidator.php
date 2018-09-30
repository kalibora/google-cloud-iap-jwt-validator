<?php

namespace Kalibora\GoogleCloud\IdentityAwareProxy\TokenValidator;

use Jose\Component\Core\{AlgorithmManager, JWKSet};
use Jose\Component\Core\Converter\{JsonConverter, StandardConverter};
use Jose\Component\Checker;
use Jose\Component\KeyManagement\JKUFactory;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\{JWSVerifier, JWSTokenSupport, JWSLoader};
use Jose\Component\Signature\Serializer\{JWSSerializerManager, CompactSerializer};
use Http\Client\HttpClient;
use Http\Message\RequestFactory;

/**
 * See: https://cloud.google.com/iap/docs/signed-headers-howto
 */
class TokenValidator
{
    private $httpClient;
    private $requestFactory;
    private $audience;
    private $allowedTimeDrift;
    private $jsonConverter;

    private static $keySet;

    private const JWK_URL = 'https://www.gstatic.com/iap/verify/public_key-jwk';
    private const ISSUER = 'https://cloud.google.com/iap';

    public function __construct(
        HttpClient $httpClient,
        RequestFactory $requestFactory,
        string $audience,
        int $allowedTimeDrift = 0,
        ?JsonConverter $jsonConverter = null
    ) {
        $this->httpClient = $httpClient;
        $this->requestFactory = $requestFactory;
        $this->audience = $audience;
        $this->allowedTimeDrift = $allowedTimeDrift;

        if ($jsonConverter === null) {
            $jsonConverter = new StandardConverter();
        }

        $this->jsonConverter = $jsonConverter;
    }

    public function validate(string $jwt) : array
    {
        $jwsLoader = $this->createLoader();
        $claimCheckerManager = $this->createClaimCheckerManager();
        $keySet = $this->getKeySet();

        try {
            $sigIndex = 0;
            $jws = $jwsLoader->loadAndVerifyWithKeySet($jwt, $keySet, $sigIndex);
        } catch (\Exception $e) {
            throw new InvalidTokenException($e->getMessage(), $e->getCode(), $e);
        }

        try {
            $claims = $this->jsonConverter->decode($jws->getPayload());
            $claimCheckerManager->check($claims);
        } catch (Checker\InvalidClaimException | Checker\MissingMandatoryClaimException $e) {
            throw new InvalidTokenException('Invalid claim. ' . $e->getMessage(), $e->getCode(), $e);
        }

        return $claims;
    }

    public function setAudience(string $audience) : self
    {
        $this->audience = $audience;

        return $this;
    }

    public function setAllowedTimeDrift(int $allowedTimeDrift) : self
    {
        $this->allowedTimeDrift = $allowedTimeDrift;

        return $this;
    }

    private function createLoader() : JWSLoader
    {
        $algorithm = new ES256();
        $algorithmManager = AlgorithmManager::create([$algorithm]);
        $jwsVerifier = new JWSVerifier($algorithmManager);

        $serializerManager = JWSSerializerManager::create([
            new CompactSerializer($this->jsonConverter),
        ]);

        $headerCheckerManager = Checker\HeaderCheckerManager::create(
            [new Checker\AlgorithmChecker([$algorithm->name()])],
            [new JWSTokenSupport()]
        );

        return new JWSLoader($serializerManager, $jwsVerifier, $headerCheckerManager);
    }

    private function createClaimCheckerManager() : Checker\ClaimCheckerManager
    {
        return Checker\ClaimCheckerManager::create([
            new Checker\ExpirationTimeChecker($this->allowedTimeDrift),
            new Checker\IssuedAtChecker($this->allowedTimeDrift),
            new Checker\AudienceChecker($this->audience),

            // See: https://github.com/web-token/jwt-framework/issues/144#issuecomment-418868510
            new class(self::ISSUER) implements Checker\ClaimChecker {
                private $issuer;

                public function __construct(string $issuer)
                {
                    $this->issuer = $issuer;
                }

                public function checkClaim($value)
                {
                    if ($value !== $this->issuer) {
                        throw new Checker\InvalidClaimException('Bad audience.', 'iss', $value);
                    }
                }

                public function supportedClaim() : string
                {
                    return 'iss';
                }
            },
        ]);
    }

    private function getKeySet() : JWKSet
    {
        if (static::$keySet === null) {
            static::$keySet = (new JKUFactory($this->jsonConverter, $this->httpClient, $this->requestFactory))->loadFromUrl(self::JWK_URL);
        }

        return static::$keySet;
    }
}
