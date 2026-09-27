# Changelog

## 0.1.1

### Fixed

- Vanta: a risk with no likelihood or impact now exports them as null. Before, a null
  or blank score became 0 and the 1-5 clamp raised it to 1, so an unscored Vanta risk
  arrived as likelihood 1, impact 1: an assessment nobody made. Residual scores, blank
  strings and non-numeric values get the same treatment. The other adapters already
  exported an unscored risk as null, and the bundle's `BundleRisk` type allows it.

## 0.1.0

Not recorded here. This file starts at 0.1.1; the git history covers earlier changes.
