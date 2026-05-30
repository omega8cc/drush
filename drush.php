#!/usr/bin/env php
<?php

/**
 * @file
 * drush is a PHP script implementing a command line shell for Drupal.
 *
 * @requires PHP CLI 5.4.5, or newer.
 */

// PHP 8.x compatibility safety net.
//
// This is a ~2015-era Drush 8 codebase. Newer PHP releases keep promoting
// long-standing patterns to E_DEPRECATED (non-canonical casts in 8.5,
// implicitly-nullable params in 8.4, passing null to internal-function
// args in 8.1, dynamic property creation in 8.2, ...). Under Drush's
// shutdown handler a deprecation raised during bootstrap surfaces as a
// fatal "Drush command terminated abnormally due to an unrecoverable
// error" via drush_shutdown()/error_get_last(), even though a deprecation
// is not itself fatal.
//
// We mask E_DEPRECATED / E_USER_DEPRECATED from error_reporting once, at
// the earliest possible point — before preflight.inc and the files it
// includes are compiled — so compile-time deprecations in those files are
// covered too. drush_errors_on()/drush_errors_off() snapshot and restore
// error_reporting through the DRUSH_ERROR_REPORTING context, so this mask
// propagates through their on/off cycles rather than being reset to E_ALL.
//
// Specific deprecations are still fixed at the source where found; this is
// only a backstop for ones not yet hit at runtime. They remain visible by
// raising error_reporting manually when debugging. Safe on PHP 5.6-8.5.
if (defined('E_DEPRECATED')) {
  error_reporting(error_reporting() & ~E_DEPRECATED & ~E_USER_DEPRECATED);
}

require __DIR__ . '/includes/preflight.inc';
exit(drush_main());
