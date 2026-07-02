<?php

/**
 * @file
 * BOA extension filter.
 *
 * Default-deny *.drush.inc loading from BOA tenant-writable paths — but ONLY
 * for privileged BOA backend identities (the aegir master or an Octopus
 * instance user oN), which are the identities that would execute a tenant
 * *.drush.inc with cross-site authority (drupal.org #762138). Invocations by a
 * limited client user ("<instance>.ftp") run as that jailed uid with no
 * escalation, so they load their own contrib *.drush.inc unfiltered — see
 * boa_drush_extension_backend_identity(). Drush's own code (e.g.
 * /data/disk/<user>/aegir/distro/), the BOA-managed subtrees .drush/{sys,usr,
 * xts}/, all of /var/aegir/, and anything outside the deny set continue to load
 * unchanged.
 *
 * Backend opt-ins on deny-matched paths (per-Octopus-user control files under
 * /data/conf/): CiviCRM (<oN>_civicrm.txt) and elysia_cron (<oN>_elysia_cron.txt).
 * Global kill switch: /data/conf/drush_extension_filter_disabled.txt turns the
 * filter off entirely — for single-tenant operators who accept re-opening
 * #762138 on that box.
 *
 * Single source of truth for the three discovery call sites:
 *   includes/command.inc::_drush_add_commandfiles()              (filters the path)
 *   includes/annotationcommand_adapter.inc::annotationcommand_adapter_discover() (ARRAY_FILTER_USE_KEY: keys are paths)
 *   includes/preflight.inc::_drush_find_commandfiles_drush()     (ARRAY_FILTER_USE_KEY: keys are paths)
 *
 * Load-bearing trust assumption: /data/disk/<user>/aegir/ is owned by the
 * Octopus system user and is NOT tenant-writable; only /data/disk/<user>/
 * {static,distro,platforms}/ and the non-{sys,usr,xts} parts of
 * /data/disk/<user>/.drush/ are reachable by a site code contributor. The
 * deny patterns and carve-outs below encode exactly that boundary.
 *
 * The entry point boa_drush_extension_allowed() resolves its argument to an
 * absolute, symlink-free path FIRST (see boa_drush_extension_canonical_path),
 * because Drush feeds the discovery scanners module paths that are RELATIVE to
 * the Drupal root (drupal_get_path()) during site/full bootstrap — a relative
 * path would otherwise dodge every '^/...'-anchored deny pattern.
 */

/**
 * Basenames of *.drush.inc files trusted for the CiviCRM exception.
 * Loaded only when the per-Octopus-user control file is present.
 *
 * @return string[]
 */
function boa_drush_extension_allowlist() {
  return array(
    'civicrm.drush.inc',
    'cv.drush.inc',
    'civicrm_drush.drush.inc',
  );
}

/**
 * Deny patterns: anchored on BOA canonical roots. The positional difference
 * between /data/disk/<user>/aegir/distro/ (Drush's own install) and
 * /data/disk/<user>/distro/ (tenant codebase) is preserved by the
 * [^/]+/(static|distro|platforms) anchor. /var/aegir/* is not denied
 * because the aegir master hosts no tenant sites under BOA.
 *
 * @return string[]
 */
function boa_drush_extension_deny_patterns() {
  return array(
    '#^/data/disk/[^/]+/(static|distro|platforms)(/|$)#i',
    '#^/data/disk/[^/]+/\.drush(/|$)#i',
  );
}

/**
 * Carve-outs: paths that match a deny pattern but are trusted because BOA
 * installs its own code there. The three .drush/{sys,usr,xts}/ subtrees
 * hold Provision and Aegir contrib drush extensions.
 *
 * @return string[]
 */
function boa_drush_extension_deny_exceptions() {
  return array(
    '#^/data/disk/[^/]+/\.drush/(sys|usr|xts)(/|$)#i',
  );
}

/**
 * Resolve the Octopus instance user (oN) from the process's EFFECTIVE uid, or
 * '' when the effective identity is not an Octopus instance user (aegir master,
 * root, or a limited client). Cached for the process lifetime.
 *
 * Derived from posix euid -> /etc/passwd 'dir', NOT getenv('HOME'): several BOA
 * backend calls run `su <user>` without `-`, so HOME stays the caller's (often
 * /root) while the euid is correctly oN — a HOME-based lookup would derive the
 * wrong user or none. The passwd record is root-owned and cannot be spoofed by
 * a client. Mirrors the euid idiom already used in includes/environment.inc
 * (drush_get_username) and provision (provision_current_user). The name-equals-
 * segment and no-dot tie keeps the dotted "<oN>.ftp"/"<oN>.<client>" users off
 * the instance-user path even if a home were ever mis-set under /data/disk.
 *
 * @return string
 *   The Octopus instance user name, or '' if not an instance user.
 */
function boa_drush_extension_octopus_user() {
  static $user = NULL;
  if ($user !== NULL) {
    return $user;
  }
  $user = '';
  if (function_exists('posix_geteuid') && function_exists('posix_getpwuid')) {
    $pw = posix_getpwuid(posix_geteuid());
    if (is_array($pw) && isset($pw['name']) && isset($pw['dir'])) {
      $dir = rtrim($pw['dir'], '/');
      if (strpos($pw['name'], '.') === FALSE
        && preg_match('#^/data/disk/([^/]+)$#', $dir, $m)
        && $m[1] === $pw['name']) {
        $user = $pw['name'];
      }
    }
  }
  return $user;
}

/**
 * Returns TRUE only when the process runs as a privileged BOA BACKEND identity
 * — the aegir master (/var/aegir) or an Octopus instance user (/data/disk/oN)
 * — i.e. an identity that runs hostmaster/provision backend tasks and would
 * execute a tenant *.drush.inc with cross-site authority. Cached.
 *
 * This is the discriminator that fixes the over-blocking: the #762138 threat is
 * privilege ESCALATION (tenant code auto-loaded as aegir/oN during a backend
 * task). A limited client user ("<instance>.ftp", HOME /home/<u>.ftp, jailed
 * lshell/SFTP, satellite.sh.inc) running its own `drush @site` escalates to
 * nothing — it already owns that uid — so its own contrib *.drush.inc must load
 * unfiltered. Only backend identities are subject to the deny set.
 *
 * Keyed on posix euid -> passwd 'dir' (kernel-enforced, root-owned, not
 * spoofable downward by a client), NOT getenv('HOME') (inherited/spoofable;
 * `su` without `-` leaves HOME=/root on a privileged backend) and NOT the
 * DRUSH_BACKEND context (unset at the earliest discovery site and merely a
 * --backend option, not an identity).
 *
 * Fail-closed: when the posix extension is unavailable, or the effective uid is
 * root, the deny set stays ON (only limited-client convenience is ever lost,
 * never the #762138 defence). posix is universally present on the BOA CLI
 * (includes/environment.inc already hard-depends on it).
 *
 * @return bool
 */
function boa_drush_extension_backend_identity() {
  static $is_backend = NULL;
  if ($is_backend !== NULL) {
    return $is_backend;
  }
  if (!function_exists('posix_geteuid') || !function_exists('posix_getpwuid')) {
    $is_backend = TRUE;
    return $is_backend;
  }
  $euid = posix_geteuid();
  if ($euid === 0) {
    $is_backend = TRUE;
    return $is_backend;
  }
  $is_backend = FALSE;
  $pw = posix_getpwuid($euid);
  if (is_array($pw) && isset($pw['name']) && isset($pw['dir'])) {
    $dir = rtrim($pw['dir'], '/');
    if ($dir === '/var/aegir' && $pw['name'] === 'aegir') {
      $is_backend = TRUE;
    }
    elseif (boa_drush_extension_octopus_user() !== '') {
      $is_backend = TRUE;
    }
  }
  return $is_backend;
}

/**
 * Global kill switch: when /data/conf/drush_extension_filter_disabled.txt
 * exists the filter is OFF for every identity, restoring stock Drush
 * *.drush.inc loading (including the backend). Intended ONLY for single-tenant
 * operators who are the sole tenant on the box and accept re-opening #762138
 * there. Cached.
 *
 * @return bool
 */
function boa_drush_extension_filter_disabled() {
  static $disabled = NULL;
  if ($disabled !== NULL) {
    return $disabled;
  }
  $disabled = file_exists('/data/conf/drush_extension_filter_disabled.txt');
  return $disabled;
}

/**
 * Returns TRUE when the per-Octopus-user CiviCRM control file is present
 * (/data/conf/<oN>_civicrm.txt). Cached. The instance user is resolved from the
 * effective uid (boa_drush_extension_octopus_user), not HOME. Consulted only
 * for backend identities — a limited client's own drush is already allowed
 * unfiltered before this is reached.
 *
 * @return bool
 */
function boa_drush_extension_civicrm_enabled() {
  static $enabled = NULL;
  if ($enabled !== NULL) {
    return $enabled;
  }
  $user = boa_drush_extension_octopus_user();
  $enabled = ($user !== '' && file_exists('/data/conf/' . $user . '_civicrm.txt'));
  return $enabled;
}

/**
 * Returns TRUE when the per-Octopus-user elysia_cron opt-in control file is
 * present (/data/conf/<oN>_elysia_cron.txt). Cached. Opting in lets the BACKEND
 * (oN) load elysia_cron.drush.inc so backend-cron mode (hosting_cron_use_backend
 * -> provision_backend_invoke @site elysia-cron, hosting_cron.module) keeps
 * elysia's scheduled granularity instead of degrading to core cron. A
 * deliberate, explicit trust widening for that one basename — off by default.
 *
 * @return bool
 */
function boa_drush_extension_elysia_enabled() {
  static $enabled = NULL;
  if ($enabled !== NULL) {
    return $enabled;
  }
  $user = boa_drush_extension_octopus_user();
  $enabled = ($user !== '' && file_exists('/data/conf/' . $user . '_elysia_cron.txt'));
  return $enabled;
}

/**
 * Resolve a candidate path to an absolute, symlink-free form so the anchored
 * deny patterns can match.
 *
 * Drush hands the discovery scanners paths that are RELATIVE to the Drupal
 * root (drupal_get_path() / extension.list.module->getPath()) during site and
 * full bootstrap. Left as-is, a relative tenant path such as
 * 'sites/all/modules/evil/evil.drush.inc' matches none of the '^/...' deny
 * patterns and would load. realpath() resolves it against the cwd (the Drupal
 * root at bootstrap time), collapses '..', and follows symlinks — closing the
 * relative-path, '..' and symlink evasions in one step.
 *
 * Stream-wrapper paths (phar://, vfs://, ...) are returned untouched: realpath
 * does not apply to them and Drush legitimately ships phar-packaged
 * commandfiles (see the "phar:// locations" note in command.inc). They simply
 * fall through to the default-allow path, preserving prior behaviour.
 *
 * If realpath() fails (e.g. a cached entry whose file is gone) but the path is
 * relative, it is absolutised lexically against the cwd so a tenant-relative
 * path still reaches the deny patterns — fail toward DENY, never silent allow.
 *
 * @param string $path
 * @return string
 */
function boa_drush_extension_canonical_path($path) {
  if (!is_string($path) || $path === '') {
    return $path;
  }
  if (strpos($path, '://') !== FALSE) {
    return $path;
  }
  $resolved = @realpath($path);
  if ($resolved !== FALSE && $resolved !== '') {
    return $resolved;
  }
  if ($path[0] !== '/') {
    $cwd = getcwd();
    if ($cwd !== FALSE && $cwd !== '') {
      return rtrim($cwd, '/') . '/' . $path;
    }
  }
  return $path;
}

/**
 * Returns TRUE when $canonical_path lies under a deny pattern and is not
 * covered by any carve-out.
 *
 * @param string $canonical_path
 *   Absolute, canonicalised filesystem path of a candidate *.drush.inc file.
 *
 * @return bool
 */
function boa_drush_extension_path_denied($canonical_path) {
  $denied = FALSE;
  foreach (boa_drush_extension_deny_patterns() as $pat) {
    if (preg_match($pat, $canonical_path)) {
      $denied = TRUE;
      break;
    }
  }
  if (!$denied) {
    return FALSE;
  }
  foreach (boa_drush_extension_deny_exceptions() as $pat) {
    if (preg_match($pat, $canonical_path)) {
      return FALSE;
    }
  }
  return TRUE;
}

/**
 * Returns TRUE when a *.drush.inc file at $path is permitted to load. This is
 * the public entry point used by the three discovery call sites. The argument
 * may be absolute OR relative (Drush passes relative module paths at bootstrap)
 * — it is resolved to absolute before matching.
 *
 * Order of checks:
 *   1. Global kill switch present            -> allow (filter off entirely).
 *   2. Not a privileged backend identity     -> allow (limited client's own
 *      drush loads its own contrib *.drush.inc; no escalation possible).
 *   3. Path not on tenant-writable territory -> allow.
 *   4. Otherwise deny, unless the basename is opted-in per Octopus user
 *      (CiviCRM / elysia_cron control files).
 *
 * @param string $path
 *   Filesystem path of a candidate *.drush.inc file (absolute or relative).
 *
 * @return bool
 */
function boa_drush_extension_allowed($path) {
  if (boa_drush_extension_filter_disabled()) {
    return TRUE;
  }
  if (!boa_drush_extension_backend_identity()) {
    return TRUE;
  }
  $path = boa_drush_extension_canonical_path($path);
  if (!boa_drush_extension_path_denied($path)) {
    return TRUE;
  }
  return boa_drush_extension_basename_allowed(basename($path));
}

/**
 * Per-Octopus-user opt-in allowlist for backend-loaded contrib *.drush.inc
 * basenames on deny-matched paths: CiviCRM (civicrm/cv/civicrm_drush) when the
 * CiviCRM control file is present, and elysia_cron when the elysia_cron control
 * file is present. Everything else on a deny-matched path stays denied.
 *
 * @param string $basename
 *   Basename of a deny-matched candidate *.drush.inc file.
 *
 * @return bool
 */
function boa_drush_extension_basename_allowed($basename) {
  if (boa_drush_extension_civicrm_enabled()
    && in_array($basename, boa_drush_extension_allowlist(), TRUE)) {
    return TRUE;
  }
  if (boa_drush_extension_elysia_enabled()
    && $basename === 'elysia_cron.drush.inc') {
    return TRUE;
  }
  return FALSE;
}
