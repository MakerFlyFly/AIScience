---
title: Robustness of the Mean and Median under Normal Contamination
lang: en
author: AIScience Demo Team
---

# Abstract

<!-- claim:claim_19fe5d517217857e0bd0b --> Under the pre-registered synthetic setting, the sample mean had RMSE 0.492, while the sample median had RMSE 0.178; the median reduced RMSE by 63.8%.

# Design

We generated 200 samples of size 50 from a centered normal mixture with 10% contamination. Robust estimation is motivated by classical work [@huber1964].

# Results

<!-- claim:claim_19fe5d51721babb86e3dd --> Figure 1 reports the fixed-seed result (mean at left; median at right). These values describe this simulation only and do not establish universal superiority.

![Estimator RMSE](../figures/robustness.png){#fig:robustness}

# Limitations

This demo uses one distribution, one sample size, and one fixed simulation seed. The local literature record is an abstract-only test fixture, not a systematic review.

# AI Use Disclosure

AI agents assisted workflow orchestration and drafting; all claims are bound to the audited local ledger.
