<?php
declare(strict_types=1);

namespace Stromcom\AuthClient\Http;

use Stromcom\AuthClient\Exception\TransportException;

interface HttpClientInterface {

  /**
   * @param array<string, string> $headers
   *
   * @throws TransportException
   */
  public function request(string $method, string $url, array $headers = [], ?string $body = null): RawResponse;

}
