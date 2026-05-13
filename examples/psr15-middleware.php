<?php
declare(strict_types=1);

/**
 * Reusable PSR-15 middleware that verifies an inbound Bearer JWT and
 * attaches the parsed Claims to the request as an attribute.
 *
 * Drop this into any PSR-15 stack (Slim, Mezzio, Laminas, Symfony's PSR-15
 * adapter). The downstream handler reads `$request->getAttribute('claims')`.
 */

require __DIR__ . '/../vendor/autoload.php';

use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Stromcom\AuthClient\Claims;
use Stromcom\AuthClient\Client;
use Stromcom\AuthClient\Exception\AuthorizationException;
use Stromcom\AuthClient\Exception\TokenVerificationException;

final class AuthMiddleware implements MiddlewareInterface {

  /**
   * @param list<string> $requiredGroups
   * @param list<string> $requiredRoles
   */
  public function __construct(
    private readonly Client $auth,
    private readonly ResponseFactoryInterface $responseFactory,
    private readonly array $requiredGroups = [],
    private readonly array $requiredRoles = [],
    private readonly bool $requireUserToken = false,
    private readonly string $attributeName = 'claims',
  ) {}

  public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface {
    $jwt = self::extractBearer($request);
    if ($jwt === null) {
      return $this->error(401, 'missing_bearer_token', 'Authorization: Bearer <jwt> required.');
    }

    try {
      $claims = $this->auth->verify($jwt);
      if ($this->requireUserToken) {
        $claims->requireUserToken();
      }
      foreach ($this->requiredGroups as $group) {
        $claims->requireGroup($group);
      }
      foreach ($this->requiredRoles as $role) {
        $claims->requireRole($role);
      }
    } catch (TokenVerificationException $e) {
      return $this->error(401, 'invalid_token', $e->getMessage());
    } catch (AuthorizationException $e) {
      return $this->error(403, 'forbidden', $e->getMessage());
    }

    return $handler->handle($request->withAttribute($this->attributeName, $claims));
  }

  private static function extractBearer(ServerRequestInterface $request): ?string {
    $header = $request->getHeaderLine('Authorization');
    if (!preg_match('/^Bearer\s+(.+)$/i', $header, $m)) {
      return null;
    }
    return $m[1];
  }

  private function error(int $status, string $code, string $message): ResponseInterface {
    $response = $this->responseFactory->createResponse($status);
    $response->getBody()->write(json_encode(['error' => $code, 'message' => $message]) ?: '');
    return $response->withHeader('Content-Type', 'application/json');
  }
}

/*
 * Usage with Slim 4:
 *
 *   $app->get('/api/things', function ($request, $response) {
 *       $claims = $request->getAttribute('claims');
 *       assert($claims instanceof Claims);
 *       $response->getBody()->write(json_encode([
 *           'sub' => $claims->subject,
 *           'groups' => $claims->groups,
 *       ]));
 *       return $response->withHeader('Content-Type', 'application/json');
 *   })->add(new AuthMiddleware(
 *       $auth,
 *       $app->getResponseFactory(),
 *       requiredGroups: ['translate-editor'],
 *       requireUserToken: true,
 *   ));
 */
