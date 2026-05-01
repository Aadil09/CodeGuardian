'use strict';

const { DataTypes, Model } = require('sequelize');
const bcrypt = require('bcryptjs');
const { sequelize } = require('../config/database');

class User extends Model {
  async comparePassword(candidatePassword) {
    return bcrypt.compare(candidatePassword, this.password);
  }

  toPublic() {
    const values = this.get({ plain: true });
    delete values.password;
    delete values.externalSessionCookie;
    values.full_name = values.name;
    values.hasGithubToken = !!values.githubToken;
    return values;
  }
}

User.init(
  {
    id: {
      type: DataTypes.INTEGER.UNSIGNED,
      autoIncrement: true,
      primaryKey: true,
    },
    email: {
      type: DataTypes.STRING(255),
      allowNull: false,
      // No unique constraint — duplicates checked manually in service layer
      validate: {
        isEmail: { msg: 'Invalid email format' },
        notEmpty: true,
      },
      set(value) {
        this.setDataValue('email', value.trim().toLowerCase());
      },
    },
    password: {
      type: DataTypes.STRING(255),
      allowNull: false,
    },
    name: {
      type: DataTypes.STRING(100),
      allowNull: false,
      validate: { len: [2, 100], notEmpty: true },
    },
    githubToken: {
      type: DataTypes.TEXT,
      allowNull: true,
      defaultValue: null,
    },
    githubUrl: {
      type: DataTypes.STRING(255),
      defaultValue: 'https://api.github.com',
    },
    externalSessionCookie: {
      type: DataTypes.TEXT,
      allowNull: true,
      defaultValue: null,
    },
    lastLogin: {
      type: DataTypes.DATE,
      allowNull: true,
    },
    isActive: {
      type: DataTypes.BOOLEAN,
      defaultValue: true,
    },
    isDeleted: {
      type: DataTypes.BOOLEAN,
      defaultValue: false,
    },
  },
  {
    sequelize,
    modelName: 'User',
    tableName: 'users',
    hooks: {
      beforeCreate: async (user) => {
        if (user.password) {
          user.password = await bcrypt.hash(user.password, 12);
        }
      },
      beforeUpdate: async (user) => {
        if (user.changed('password')) {
          user.password = await bcrypt.hash(user.password, 12);
        }
      },
    },
  }
);

module.exports = User;
