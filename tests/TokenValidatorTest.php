<?php

namespace Kalibora\GoogleCloud\IdentityAwareProxy\TokenValidator;

use Http\Mock\Client;
use Http\Message\MessageFactory\GuzzleMessageFactory;
use Psr\Http\Message\{ResponseInterface, StreamInterface};
use PHPUnit\Framework\TestCase;

class TokenValidatorTest extends TestCase
{
    private $validator;

    // sub: "accounts.google.com:117906422442754941368"
    // exp: 1538302173
    // iat: 1538301573
    private const VALID_TOKEN = 'eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InJUbGstZyJ9.eyJpc3MiOiJodHRwczovL2Nsb3VkLmdvb2dsZS5jb20vaWFwIiwic3ViIjoiYWNjb3VudHMuZ29vZ2xlLmNvbToxMTc5MDY0MjI0NDI3NTQ5NDEzNjgiLCJlbWFpbCI6ImthbGlib3JhQGdtYWlsLmNvbSIsImF1ZCI6Ii9wcm9qZWN0cy82NTczMTUxMDk4NDkvYXBwcy9rYWxpYm9yYS10ZXN0LWlhcCIsImV4cCI6MTUzODMwMjE3MywiaWF0IjoxNTM4MzAxNTczfQ.Bs8yr9La6OdDTjkQl2ElDRSHLky88yKWp0XvbKcYusOUASW_xx6wMh25XEcrUtsEqN4YNik4UQhvTA1tIdshsQ';

    private const AUDIENCE = '/projects/657315109849/apps/kalibora-test-iap';

    public function setUp()
    {
        $file = __DIR__ . '/public_key-jwk.json';
        $streamp = $this->prophesize(StreamInterface::class);
        $streamp->getContents()->willReturn(file_get_contents($file));

        $responsep = $this->prophesize(ResponseInterface::class);
        $responsep->getStatusCode()->willReturn(200);
        $responsep->getBody()->willReturn($streamp->reveal());

        $httpClient = new Client();
        $httpClient->addResponse($responsep->reveal());

        $messageFactory = new GuzzleMessageFactory();

        $this->validator = new TokenValidator($httpClient, $messageFactory, self::AUDIENCE);
    }

    /**
     * @test
     */
    public function invalidFormatToken()
    {
        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessageRegExp('/Unable to load and verify the token/i');

        $this->validator->validate('invalid_format_token');
    }

    /**
     * @test
     */
    public function invalidSignature()
    {
        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessageRegExp('/Unable to load and verify the token/i');

        $this->validator->validate('eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InJUbGstZyJ9.eyJpc3MiOiJodHRwczovL2Nsb3VkLmdvb2dsZS5jb20vaWFwIiwic3ViIjoiYWNjb3VudHMuZ29vZ2xlLmNvbToxMTc5MDY0MjI0NDI3NTQ5NDEzNjgiLCJlbWFpbCI6ImthbGlib3JhQGdtYWlsLmNvbSIsImF1ZCI6Ii9wcm9qZWN0cy82NTczMTUxMDk4NDkvYXBwcy9rYWxpYm9yYS10ZXN0LWlhcCIsImV4cCI6MTUzODMwMjE3MywiaWF0IjoxNTM4MzAxNTczfQ.INVALIDSIGNATURE');
    }

    /**
     * @test
     */
    public function expiredToken()
    {
        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessageRegExp('/expired/i');

        $this->validator->validate(self::VALID_TOKEN);
    }

    /**
     * @test
     */
    public function differentAudience()
    {
        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessageRegExp('/Bad audience/i');

        $this->validator->setAllowedTimeDrift(86400 * 365 * 100); // 100 years
        $this->validator->setAudience('foo');
        $this->validator->validate(self::VALID_TOKEN);
    }

    /**
     * @test
     */
    public function success()
    {
        $this->validator->setAllowedTimeDrift(86400 * 365 * 100); // 100 years
        $claims = $this->validator->validate(self::VALID_TOKEN);

        $this->assertEquals('accounts.google.com:117906422442754941368', $claims['sub']);
    }
}
