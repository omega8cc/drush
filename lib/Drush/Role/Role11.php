<?php

namespace Drush\Role;

use Drupal\user\Entity\Role;

class Role11 extends Role9 {

  /**
   * This constructor will allow the role to be selected either
   * via the role id or via the role name.
   */
  public function __construct($rid = NULL) {
    if ($rid === NULL) {
      $rid = $this->anonymousRole();
    }
    $this->roles = Role::loadMultiple();
    // In D8+, rids are always machine names (strings), never numeric.
    // First check if $rid is already a valid machine name;
    // if not, try to match it as a human-readable role label.
    if (!isset($this->roles[$rid])) {
      $role_name = $rid;
      foreach ($this->roles as $machine_name => $role) {
        if ($role->label() === $role_name) {
          $rid = $machine_name;
          break;
        }
      }
    }

    if (isset($this->roles[$rid])) {
      $this->rid = $rid;
      // In D8+ Role is an object.
      $this->name = is_object($this->roles[$rid]) ? $this->roles[$rid]->label() : $this->roles[$rid];
    }
    else {
      throw new RoleException(dt('Could not find the role: !role', array('!role' => $rid)));
    }
  }

}
