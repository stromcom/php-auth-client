<?php
declare(strict_types=1);

/**
 * Patterns for scope-, role- and group-based authorization on top of a
 * verified JWT.
 *
 * All examples assume `$claims = $auth->verify($jwt);` has succeeded.
 */

require __DIR__ . '/../vendor/autoload.php';

use Stromcom\AuthClient\Claims;
use Stromcom\AuthClient\Exception\AuthorizationException;

// ---------------------------------------------------------------------------
// 1. Simple guard: require a single role.
// ---------------------------------------------------------------------------
function requireEditor(Claims $claims): void {
  $claims->requireRole('translator.editor');
}

// ---------------------------------------------------------------------------
// 2. Any of several roles (typical "editor OR admin").
// ---------------------------------------------------------------------------
function requireEditorOrAdmin(Claims $claims): void {
  $claims->requireAnyRole('translator.editor', 'translator.admin');
}

// ---------------------------------------------------------------------------
// 3. Per-project authorization without hard-coding the project prefix.
// ---------------------------------------------------------------------------
function rolesInProject(Claims $claims, string $projectPrefix): array {
  return $claims->rolesForProject($projectPrefix);
}

// Example: a generic CMS that hosts multiple projects.
// $myProject = 'deploy';
// if ($claims->hasProjectRole($myProject, 'admin')) { ... }

// ---------------------------------------------------------------------------
// 4. Group membership for feature flags.
// ---------------------------------------------------------------------------
function canUseBetaFeature(Claims $claims): bool {
  return $claims->hasAnyGroup('beta', 'early-access');
}

// ---------------------------------------------------------------------------
// 5. Scope check: the requesting client granted permission for this data.
// ---------------------------------------------------------------------------
function returnEmail(Claims $claims): ?string {
  // The auth server filters `email` out of the JWT unless `email` scope was
  // granted. But the consumer should ALSO assert it, in case a future server
  // change ever lets a token through without proper scope.
  if (!$claims->hasScope('email')) {
    return null;
  }
  return $claims->email;
}

// ---------------------------------------------------------------------------
// 6. Require a user token specifically (reject service tokens).
// ---------------------------------------------------------------------------
function requireHumanUser(Claims $claims): void {
  $claims->requireUserToken();
}

// ---------------------------------------------------------------------------
// 7. Require a service token specifically (typical for /internal endpoints).
// ---------------------------------------------------------------------------
function requireServiceCaller(Claims $claims): void {
  $claims->requireServiceToken();
}

// ---------------------------------------------------------------------------
// 8. Authorization helper combining several checks with audit context.
// ---------------------------------------------------------------------------
function authorize(Claims $claims, string $resource, string $action): void {
  try {
    $claims->requireUserToken();
    match ($action) {
      'read'   => $claims->requireAnyRole("{$resource}.viewer", "{$resource}.editor", "{$resource}.admin"),
      'write'  => $claims->requireAnyRole("{$resource}.editor", "{$resource}.admin"),
      'delete' => $claims->requireRole("{$resource}.admin"),
      default  => throw new \LogicException("Unknown action: {$action}"),
    };
  } catch (AuthorizationException $e) {
    error_log(sprintf(
      'forbidden: subject=%s resource=%s action=%s reason=%s',
      $claims->subject, $resource, $action, $e->getMessage(),
    ));
    throw $e;
  }
}

// authorize($claims, 'translator', 'write');

// ---------------------------------------------------------------------------
// 9. Multi-tenant: derive tenant from claims, then check tenant membership.
// ---------------------------------------------------------------------------
function requireTenantMember(Claims $claims, string $tenantSlug): void {
  $group = "tenant-{$tenantSlug}";
  if (!$claims->hasGroup($group)) {
    throw AuthorizationException::missingGroup($group);
  }
}

// ---------------------------------------------------------------------------
// 10. Sliding authorization: admins bypass per-resource checks.
// ---------------------------------------------------------------------------
function requireOwnerOrAdmin(Claims $claims, string $resourceOwnerSubject): void {
  if ($claims->isAdmin) {
    return;
  }
  if ($claims->subject !== $resourceOwnerSubject) {
    throw AuthorizationException::missingRole('owner');
  }
}
