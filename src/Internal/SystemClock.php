<?php
declare(strict_types=1);

namespace Stromcom\AuthClient\Internal;

use DateTimeImmutable;
use Psr\Clock\ClockInterface;

/**
 * Minimal PSR-20 clock for lcobucci/jwt's temporal constraints. Picking this
 * over `lcobucci/clock` avoids one more transitive dependency for a class
 * that's literally one method.
 *
 * @internal
 */
final class SystemClock implements ClockInterface {

  public function now(): DateTimeImmutable {
    return new DateTimeImmutable('now');
  }

}
