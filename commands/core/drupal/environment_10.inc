<?php
/**
 * @file
 *   Specific functions for a drupal 10 environment.
 *   drush_include_engine() magically includes either this file
 *   or environment_X.inc depending on which version of drupal Drush
 *   is called from.
 */

use Drupal\Core\Extension\ExtensionDiscovery;

include __DIR__ . '/environment_common.inc';

function drush_user_load($uid) {
  return user_load($uid);
}

/**
 * Return dependencies and its status for modules.
 *
 * @param $modules
 *   Array of module names
 * @param $module_info
 *   Drupal 'files' array for modules as returned by drush_get_modules().
 * @return
 *   Array with dependencies and status for $modules
 */
function drush_check_module_dependencies($modules, $module_info) {
  $status = array();
  foreach ($modules as $key => $module) {
    $dependencies = array_reverse($module_info[$module]->requires);
    $unmet_dependencies = array_diff(array_keys($dependencies), array_keys($module_info));
    if (!empty($unmet_dependencies)) {
      $status[$key]['error'] = array(
          'code' => 'DRUSH_PM_ENABLE_DEPENDENCY_NOT_FOUND',
          'message' => dt('Module !module cannot be enabled because it depends on the following modules which could not be found: !unmet_dependencies', array('!module' => $module, '!unmet_dependencies' => implode(',', $unmet_dependencies)))
      );
    }
    else {
      // check for version incompatibility
      foreach ($dependencies as $dependency_name => $v) {
        $current_version = $module_info[$dependency_name]->info['version'];
        $current_version = str_replace(drush_get_drupal_core_compatibility() . '-', '', $current_version);
        if (!$v->isCompatible($current_version)) {
          $status[$key]['error'] = array(
            'code' => 'DRUSH_PM_ENABLE_DEPENDENCY_VERSION_MISMATCH',
            'message' => dt('Module !module cannot be enabled because it depends on !dependency !required_version but !current_version is available', array('!module' => $module, '!dependency' => $dependency_name, '!required_version' => $v->getConstraintString(), '!current_version' => $current_version))
          );
        }
      }
    }
    $status[$key]['unmet-dependencies'] = $unmet_dependencies;
    $status[$key]['dependencies'] = $dependencies;
  }

  return $status;
}

/**
 * Returns an array of modules required by core.
 * 
 * Deprecated in drupal:9.4.0 and is removed from drupal:10.0.0
 */
function function drupal_required_modules() {
   
    $listing = new ExtensionDiscovery(\Drupal::root());
    $files = $listing->scan('module');
    $required = [];
    // Unless called by the installer, an installation profile is required and
    // must always be loaded.
    if ($profile = \Drupal::installProfile()) {
        $required[] = $profile;
    }
    foreach ($files as $name => $file) {
        $info = \Drupal::service('info_parser')->parse($file->getPathname());
        if (!empty($info) && !empty($info['required']) && $info['required']) {
            $required[] = $name;
        }
    }
    return $required;
}
