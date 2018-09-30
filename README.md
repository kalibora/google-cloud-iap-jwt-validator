# Google Cloud Identity-Aware Proxy JWT (Json Web Token) Validator

See: https://cloud.google.com/iap/docs/signed-headers-howto

## Installation

Example using curl client.

```
$ composer require kalibora/google-cloud-iap-jwt-validator php-http/curl-client guzzlehttp/psr7 php-http/message
```

You can also select other clients listed below link.

http://docs.php-http.org/en/latest/clients.html

## Usage

```php
<?php

require __DIR__ . '/vendor/autoload.php';

use Kalibora\GoogleCloud\IdentityAwareProxy\TokenValidator\{TokenValidator, InvalidTokenException};
use Http\Client\Curl\Client;
use Http\Message\MessageFactory\GuzzleMessageFactory;

$audience = '/projects/{YOUR_PROJECT_NUMBER}/apps/{YOUR_PROJECT_ID};
$tokenValidator = new TokenValidator(new Client(), new GuzzleMessageFactory(), $audience);

$jwt = 'FOO.BAR.BAZ'; // HTTP request header `x-goog-iap-jwt-assertion`
try {
    $claims = $tokenValidator->validate($jwt);
} catch (InvalidTokenException $e) {
    // Invalid or expired token
    die($e->getMessage() . PHP_EOL);
}

echo $claims['sub'], PHP_EOL;
echo $claims['email'], PHP_EOL;
```
