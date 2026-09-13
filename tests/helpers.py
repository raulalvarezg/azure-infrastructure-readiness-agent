import os

SAMPLES_DIR = os.path.join(os.path.dirname(__file__), "..", "samples")


def sample_path(filename: str) -> str:
    return os.path.join(SAMPLES_DIR, filename)


def read_sample(filename: str) -> str:
    with open(sample_path(filename), "r", encoding="utf-8") as handle:
        return handle.read()
