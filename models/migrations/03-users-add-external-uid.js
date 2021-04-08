'use strict';

module.exports = {
  up: function(migration, DataTypes) {
    return Promise.all([
      migration.addColumn('users', 'external_uid', DataTypes.STRING)
    ])
  },

  down: function(migration, DataTypes) {
    return Promise.all([
      migration.removeColumn('users', 'external_uid')
    ])
  }
}
