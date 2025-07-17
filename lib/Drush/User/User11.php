<?php


namespace Drush\User;

use Drupal\user\Entity\User;

class User11 extends User9 {

  /**
   * {inheritdoc}
   */
  public function create($properties) {
    $account = \Drupal::entityTypeManager()
      ->getStorage('user')
      ->create($properties);
    $account->save();
    return new UserSingle11($account);
  }
}
