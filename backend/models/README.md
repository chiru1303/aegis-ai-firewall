# Optional model assets

Model weights and tokenizer caches are intentionally not tracked in Git because of their size. Run `install_ml_models.bat` from the repository root to install optional inference dependencies and download the supported local model assets into this directory. The base application still runs deterministic detectors without these weights. Check the dashboard's System status page to see which models actually loaded.
