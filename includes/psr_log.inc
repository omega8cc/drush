<?php

/**
 * @file
 * The psr/log interface Drush binds on PHP 8.0 and newer.
 *
 * Drush creates its logger at preflight, long before any codebase autoloader
 * exists, so the psr/log interface it binds there is the one every class in
 * the process must match. The psr/log 1 in vendor/ is untyped, while Drupal
 * 10 and 11 ship psr/log 3, and their core loggers and any logger written
 * for them declare a string|\Stringable message and ': void'. Against the v1
 * interface none of those classes can load in a Drush 8 process, which is
 * why locked platforms carried a de-typed psr/log and core.
 *
 * psr/log 2.0 declares the typed message and no return type. A typed logger
 * (stock Drupal 10 and 11 core, psr/log 3 users such as monolog 3) matches
 * it, and so does an untyped one (Drush itself, Drupal 7 to 9, the packages
 * in vendor/ and in provision), because an implementation may widen a
 * parameter and add a return type.
 *
 * Only the interface and the logger base classes are bound here, the three
 * a logger is declared against: LoggerInterface, LoggerTrait and
 * AbstractLogger. LogLevel and InvalidArgumentException are the same in
 * every psr/log version. NullLogger, LoggerAwareInterface and
 * LoggerAwareTrait still come from whichever loader is asked first, as they
 * always did: their v1 forms match the v2 interface, and the v2
 * LoggerAwareTrait's typed $logger property would refuse a class written for
 * psr/log 1 that declares its own untyped one.
 *
 * psr/log 2.0 does not parse below PHP 8.0, so older PHP keeps the v1
 * package from vendor/ for all of it, exactly as before. The files are
 * php-fig/log 2.0.0 (commit ef29f6d2), MIT, unchanged, in lib/psr-log-2.
 * Provision reads the files listed below, and the drush_psr_log_bind() call
 * in preflight.inc, in each Drush 8 copy on a box to tell whether every copy
 * binds the typed interface.
 */

/**
 * The psr/log 2.0 files Drush binds, in load order, keyed by name.
 */
function drush_psr_log_typed_files() {
  $dir = dirname(dirname(__FILE__)) . '/lib/psr-log-2/src/';
  return array(
    'Psr\Log\LoggerInterface' => $dir . 'LoggerInterface.php',
    'Psr\Log\LoggerTrait' => $dir . 'LoggerTrait.php',
    'Psr\Log\AbstractLogger' => $dir . 'AbstractLogger.php',
  );
}

/**
 * Bind the psr/log 2.0 interface and logger base on PHP 8.0 and newer.
 *
 * Called before any autoloader is registered. Loads nothing when PHP is
 * older, when one of the names is already declared, or when one of the
 * files is missing, so a process never mixes the two versions of these
 * three.
 *
 * @return bool
 *   TRUE when the typed interface was bound by this call.
 */
function drush_psr_log_bind() {
  if (PHP_VERSION_ID < 80000) {
    return FALSE;
  }
  $files = drush_psr_log_typed_files();
  foreach ($files as $name => $file) {
    if (interface_exists($name, FALSE) || trait_exists($name, FALSE) || class_exists($name, FALSE) || !is_file($file)) {
      return FALSE;
    }
  }
  foreach ($files as $file) {
    require_once $file;
  }
  return TRUE;
}
