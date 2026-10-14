<?php


namespace Drush\User;

use Drupal\user\Entity\User;

class User12 extends User9 {

  /**
   * {inheritdoc}
   */
  public function create($properties) {
    $account = \Drupal::entityTypeManager()
      ->getStorage('user')
      ->create($properties);
    $account->save();
    return new UserSingle12($account);
  }
}
