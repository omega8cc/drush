<?php

/**
 * @file
 * BOA extension filter.
 *
 * Default-deny *.drush.inc loading from BOA tenant-writable paths, with a
 * per-Octopus-user CiviCRM opt-in via /data/conf/<user>_civicrm.txt. Drush
 * own code (e.g. /data/disk/<user>/aegir/distro/), the BOA-managed subtrees
 * .drush/{sys,usr,xts}/, all of /var/aegir/, and anything outside the deny
 * set continue to load unchanged.
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
 * Returns TRUE when the per-Octopus-user CiviCRM control file is present.
 * Cached for the lifetime of the PHP process.
 *
 * Octopus user is derived from HOME matching /data/disk/<user>; same
 * convention used by other BOA-aware code in this codebase
 * (includes/filesystem.inc, includes/sitealias.inc).
 *
 * When HOME is /var/aegir or unrecognised, returns FALSE — but /var/aegir
 * paths are not subject to the deny patterns in the first place, so the
 * default is safe.
 *
 * @return bool
 */
function boa_drush_extension_civicrm_enabled() {
  static $enabled = NULL;
  if ($enabled !== NULL) {
    return $enabled;
  }
  $home = getenv('HOME');
  if ($home && preg_match('#^/data/disk/([^/]+)#', $home, $m)) {
    $enabled = file_exists('/data/conf/' . $m[1] . '_civicrm.txt');
  }
  else {
    $enabled = FALSE;
  }
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
 * Returns TRUE when a *.drush.inc file at $canonical_path is permitted to
 * load. FALSE means the file is on tenant-writable territory AND (the
 * CiviCRM control file is absent OR the basename is not on the allowlist).
 *
 * This is the public entry point used by the three discovery call sites. The
 * argument may be absolute OR relative (Drush passes relative module paths at
 * bootstrap) — it is resolved to absolute here before matching.
 *
 * @param string $path
 *   Filesystem path of a candidate *.drush.inc file (absolute or relative).
 *
 * @return bool
 */
function boa_drush_extension_allowed($path) {
  $path = boa_drush_extension_canonical_path($path);
  if (!boa_drush_extension_path_denied($path)) {
    return TRUE;
  }
  if (!boa_drush_extension_civicrm_enabled()) {
    return FALSE;
  }
  return in_array(basename($path), boa_drush_extension_allowlist(), TRUE);
}
