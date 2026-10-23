import os

# A not_determined verdict without a reason is a bug here, not a row to report as "unexplained".
os.environ["PSAT_LOGIC_STRICT_GAPS"] = "1"
