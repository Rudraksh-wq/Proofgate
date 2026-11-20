from proofgate.models import Contract, Finding, FixResult, Report
from proofgate.sample import SAMPLE_CONTRACT, SAMPLE_FINDING, SAMPLE_FIX, sample_report


def test_sample_data_matches_models():
    Finding(**SAMPLE_FINDING)
    Contract(**SAMPLE_CONTRACT)
    FixResult(**SAMPLE_FIX)
    Report(**sample_report("demo"))
