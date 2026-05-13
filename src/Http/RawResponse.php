<?php
declare(strict_types=1);

namespace Stromcom\AuthClient\Http;

final class RawResponse {

  /**
   * @param array<string, string> $headers Lower-cased header names.
   */
  public function __construct(
    public readonly int $statusCode,
    public readonly string $body,
    public readonly array $headers = [],
  ) {}

}
