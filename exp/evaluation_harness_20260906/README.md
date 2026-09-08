# Offline evaluation harness

既存コードのロジックを変更せずに合成評価・保存pcap再評価を実行する。
入口は`run.sh`（rootからは`bash scripts/run_evaluation.sh`）、実行は`run.py`、成果物検証は`analyze.py`。
条件は[configs](../../configs/README.md)、再現手順と制約は[EXPERIMENTS](../../docs/EXPERIMENTS.md)を参照。
結果は`out/YYYYMMDD_HHMMSS/`に新規保存する。初期profileはsmokeで、研究の合否を示さない。
