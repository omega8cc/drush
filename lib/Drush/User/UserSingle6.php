<?php

namespace Drush\User;

class UserSingle6 extends UserSingleBase {

  public function cancel() {
    user_delete(array(), $this->account->uid);
  }
}
