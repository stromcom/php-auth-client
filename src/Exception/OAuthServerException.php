<?php
declare(strict_types=1);

namespace Stromcom\AuthClient\Exception;

final class OAuthServerException extends AuthClientException {

  /**
   * @param array<string, mixed> $raw
   */
  public function __construct(
    public readonly int $statusCode,
    public readonly string $errorCode,
    public readonly ?string $errorDescription,
    public readonly ?string $errorUri,
    public readonly array $raw,
  ) {
    parent::__construct(sprintf(
      'OAuth server error (HTTP %d): %s%s',
      $statusCode,
      $errorCode,
      $errorDescription !== null && $errorDescription !== '' ? ' — ' . $errorDescription : '',
    ));
  }

}
