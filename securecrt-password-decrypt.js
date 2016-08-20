#!/usr/bin/env node

require("babel-polyfill");

require('babel-register')({
  presets: [
    'es2015',
    'es2016',
    'stage-0',
  ],
});

require('./index');
