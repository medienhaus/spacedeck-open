'use strict';

module.exports = {
  up: function(migration, DataTypes) {
    return Promise.all([
      migration.changeColumn('users', 'external_uid',
        {
          type: DataTypes.STRING
        }
      )
    ])
  },

  down: function(migration, DataTypes) {
    return Promise.all([
      migration.removeColumn('users', 'external_uid')
    ])
  }
}
