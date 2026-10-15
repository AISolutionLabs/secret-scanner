// SPDX-License-Identifier: Apache-2.0

//go:build race

package detect_test

// The race detector slows the statistical tests ~20x without adding
// anything to them; CI runs them at full size in a separate non-race step.
const raceEnabled = true
