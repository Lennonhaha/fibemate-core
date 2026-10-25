// SPDX-License-Identifier: GPL-3.0-only
// fibemate-core — dual-environment entry
// Node.js (CJS):        require('fibemate-core')
// Browser (<script>):   window.MLKEM768 (auto-registers via core file)
'use strict';

const MLKEM768 = require('./src/kem/ml-kem-768.js');

module.exports = MLKEM768;
// Re-export for convenience: { generateKeypair, encapsulate, decapsulate, ... }
