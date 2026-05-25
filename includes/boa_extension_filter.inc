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
 *   includes/command.inc::_drush_add_commandfiles()
 *   includes/annotationcommand_adapter.inc::annotationcommand_adapter_discover()
 *   includes/preflight.inc::_drush_find_commandfiles_drush()
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
 * This is the public entry point used by the three discovery call sites.
 *
 * @param string $canonical_path
 *   Absolute, canonicalised filesystem path of a candidate *.drush.inc file.
 *
 * @return bool
 */
function boa_drush_extension_allowed($canonical_path) {
  if (!boa_drush_extension_path_denied($canonical_path)) {
    return TRUE;
  }
  if (!boa_drush_extension_civicrm_enabled()) {
    return FALSE;
  }
  return in_array(basename($canonical_path), boa_drush_extension_allowlist(), TRUE);
}
