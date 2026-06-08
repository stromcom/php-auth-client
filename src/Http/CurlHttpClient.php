<?php
declare(strict_types=1);

namespace Stromcom\AuthClient\Http;

use Stromcom\AuthClient\Exception\TransportException;

final class CurlHttpClient implements HttpClientInterface {

  public function __construct(
    public readonly int $timeout = 10,
  ) {}

  public function request(string $method, string $url, array $headers = [], ?string $body = null): RawResponse {
    $ch = curl_init();
    if ($ch === false) {
      throw new TransportException('Could not initialize cURL handle.');
    }

    $headerLines = [];
    foreach ($headers as $name => $value) {
      $headerLines[] = $name . ': ' . $value;
    }

    $responseHeaders = [];

    curl_setopt_array($ch, [
      CURLOPT_URL            => $url,
      CURLOPT_CUSTOMREQUEST  => strtoupper($method),
      CURLOPT_RETURNTRANSFER => true,
      CURLOPT_TIMEOUT        => $this->timeout,
      CURLOPT_CONNECTTIMEOUT => $this->timeout,
      CURLOPT_HTTPHEADER     => $headerLines,
      CURLOPT_FOLLOWLOCATION => false,
      CURLOPT_HEADERFUNCTION => function ($_ch, string $line) use (&$responseHeaders): int {
        $colon = strpos($line, ':');
        if ($colon !== false) {
          $name = strtolower(trim(substr($line, 0, $colon)));
          $value = trim(substr($line, $colon + 1));
          if ($name !== '') {
            $responseHeaders[$name] = $value;
          }
        }
        return strlen($line);
      },
    ]);

    if ($body !== null) {
      curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
    }

    $response = curl_exec($ch);
    if ($response === false) {
      $error = curl_error($ch);
      $errno = curl_errno($ch);
      throw new TransportException(sprintf('cURL error (%d): %s', $errno, $error));
    }

    $statusCode = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);

    return new RawResponse($statusCode, (string) $response, $responseHeaders);
  }

}
